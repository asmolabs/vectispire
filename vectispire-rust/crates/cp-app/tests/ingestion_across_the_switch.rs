//! **The backlog survives the switch** — the published Java control plane and this binary taking turns on one MySQL.
//!
//! What an installation upgraded from Java to Rust keeps is its issues and their triage, and an issue is found again
//! by its fingerprint (`AGENTS.md`: anything entering it is a data contract). If Rust fingerprinted a finding one byte
//! differently, its first scan would resolve every issue Java opened and open a twin of each — silently, on every
//! target. So, on one database:
//!
//! 1. Java ingests a scan finding A and B: two issues open.
//! 2. Java stops; the Rust binary starts and ingests the next scan, finding A and C: A is **the same row** and still
//!    open, B is resolved, C is new — no twin of A.
//! 3. Rust stops; Java starts again and ingests a scan finding A and C: nothing new — Java finds the row Rust opened
//!    for C by its fingerprint — and B stays resolved.
//!
//! The results are sent through the agent protocol by the Rust agent's own client, so both control planes take them
//! through their result route and their ingestion, not through a test seam.
//!
//! **Docker is required, and its absence fails the test.** Containers and the network are `vs-rs-p28-*`, removed on
//! drop. The Java image is `VECTISPIRE_E2E_CONTROL_PLANE_IMAGE`, by default the last published release by digest.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use vectispire_crypto::SealingKeyPair;
use vectispire_domain::secret::Secret;
use vectispire_protocol::{AgentClient, Description, Findings, ScanArtifacts};
use vectispire_testkit::docker::{Container, docker, unique_name};
use vectispire_tls::TlsTrust;

const BINARY: &str = env!("CARGO_BIN_EXE_vectispire-control-plane");
const DEFAULT_IMAGE: &str =
    "ghcr.io/asmolabs/vectispire:1.0.0-rc.2@sha256:1058a81a5d01426e202f041245879fbbd2a2a6fad71a3d58af92c145cf2194c2";
/// The composition's MySQL, as `docker-compose.yml` pins it.
const MYSQL_IMAGE: &str = "mysql:8.4.11@sha256:24989179f58856db763f418010c1169fecc944e3ec1ea7e921572d83eb070f70";
const DB_PASSWORD: &str = "vs-rs-p28-database-password"; // gitleaks:allow — invented, for a container removed after the test
/// Both control planes' encryption key: they share the database, so they share what it decrypts.
const CONTROL_PLANE_KEY: &str = "dnMtcnMtcDI4LWVuY3J5cHRpb24ta2V5LWludmVudCE="; // gitleaks:allow — base64 of an invented 32-byte label
const BOOTSTRAP_PASSWORD: &str = "Vs-rs-p28-bootstrap-Invented-1!"; // gitleaks:allow — invented
const ROTATED_PASSWORD: &str = "Vs-rs-p28-rotated-Invented-2!"; // gitleaks:allow — invented

struct Network(String);

impl Drop for Network {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["network", "rm", &self.0]).output();
    }
}

/// The Rust binary, stopped on drop.
struct Binary(Child);

impl Drop for Binary {
    fn drop(&mut self) {
        let _ = Command::new("kill").arg("-TERM").arg(self.0.id().to_string()).status();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn healthy(base: &str, what: &str, logs: impl Fn() -> String) {
    let http = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if http.get(format!("{base}/actuator/health")).send().await.is_ok_and(|r| r.status().is_success()) {
            return;
        }
        assert!(Instant::now() < deadline, "{what} did not become healthy: {}", logs());
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// MySQL on a network of its own, its port also published on the loopback interface for the binary.
fn database(network: &Network) -> Container {
    let mysql_password = format!("MYSQL_PASSWORD={DB_PASSWORD}");
    let mysql_root = format!("MYSQL_ROOT_PASSWORD={DB_PASSWORD}");
    let database = Container::run(
        "p28-mysql",
        &[
            "--network",
            &network.0,
            "--network-alias",
            "db",
            "-p",
            "127.0.0.1::3306",
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
    database
}

/// The published Java control plane on that database; it migrates it on its first start.
async fn java(network: &Network) -> (Container, String) {
    let image = std::env::var("VECTISPIRE_E2E_CONTROL_PLANE_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_owned());
    let variables = [
        "VECTISPIRE_DB_URL=jdbc:mysql://db:3306/vectispire".to_owned(),
        "VECTISPIRE_DB_USER=vectispire".to_owned(),
        format!("VECTISPIRE_DB_PASSWORD={DB_PASSWORD}"),
        format!("ENCRYPTION_KEY={CONTROL_PLANE_KEY}"),
        "VECTISPIRE_BOOTSTRAP_USERNAME=admin".to_owned(),
        format!("VECTISPIRE_BOOTSTRAP_PASSWORD={BOOTSTRAP_PASSWORD}"),
        "VECTISPIRE_EMBEDDED_WORKER=false".to_owned(),
    ];
    let mut arguments = vec!["--network", network.0.as_str(), "-p", "127.0.0.1::3180"];
    for variable in &variables {
        arguments.extend(["-e", variable.as_str()]);
    }
    arguments.push(image.as_str());
    let app = Container::run("p28-java", &arguments);
    let base = format!("http://127.0.0.1:{}", app.host_port("3180/tcp"));
    let name = app.name.clone();
    healthy(&base, "the Java control plane", || docker(&["logs", "--tail", "60", &name])).await;
    (app, base)
}

/// This commit's binary on the same database, its worker off: the agent's client is the only scanner.
async fn rust(database: &Container) -> (Binary, String) {
    let port = free_port();
    let child = Command::new(BINARY)
        .env("VECTISPIRE_DB_URL", format!("jdbc:mysql://127.0.0.1:{}/vectispire", database.host_port("3306/tcp")))
        .env("VECTISPIRE_DB_USER", "vectispire")
        .env("VECTISPIRE_DB_PASSWORD", DB_PASSWORD)
        .env("ENCRYPTION_KEY", CONTROL_PLANE_KEY)
        .env("VECTISPIRE_PORT", port.to_string())
        .env("VECTISPIRE_EMBEDDED_WORKER", "false")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let base = format!("http://127.0.0.1:{port}");
    healthy(&base, "the Rust binary", String::new).await;
    (Binary(child), base)
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
    answer["token"].as_str().unwrap_or_else(|| panic!("login refused by {base}: {answer}")).to_owned()
}

async fn call(
    http: &reqwest::Client,
    base: &str,
    session: &str,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Value {
    let mut request = http.request(method.clone(), format!("{base}{path}")).bearer_auth(session);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let answer = request.send().await.unwrap();
    let status = answer.status();
    let text = answer.text().await.unwrap();
    assert!(status.is_success(), "{method} {path} on {base}: {status} {text}");
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

/// One SAST finding: the rule and the file are what the fingerprint reads.
fn finding(file: &str) -> Value {
    json!({"ruleId": "vectispire.p28.sql-injection", "category": "injection", "severity": "HIGH", "confidence": "HIGH",
           "file": file, "line": 10, "message": "a query built from a request parameter", "owaspCategory": "A03"})
}

/// A scan of `repository` queued on `base`, claimed by the agent and answered with SAST findings in `files`; returns
/// once the scan is completed in the database.
async fn scan(
    http: &reqwest::Client,
    base: &str,
    session: &str,
    api_key: &str,
    repository: i64,
    files: &[&str],
    database: &Container,
) -> i64 {
    let client = AgentClient::new(
        base,
        Secret::new(api_key.to_owned()),
        &TlsTrust::BuiltIn,
        None,
        SealingKeyPair::generate(),
        1_760_000_000_000,
    )
    .unwrap();
    client
        .hello(&Description {
            contract_version: vectispire_domain::contract::VERSION,
            hostname: "p28-switch".into(),
            platform: "linux".into(),
            scanner_engine: "docker".into(),
            sealing_public_key: client.sealing_public_key(),
            version: Some("2.0.0-dev".into()),
            executors: None,
        })
        .await
        .unwrap();
    let id = call(http, base, session, reqwest::Method::POST, &format!("/api/v1/repositories/{repository}/scan"), None)
        .await["id"]
        .as_i64()
        .unwrap();
    let claimed = client.claim(Duration::from_secs(5)).await.unwrap().task.expect("the queued scan");
    assert_eq!(claimed.scan_id, id);
    let findings: Vec<Value> = files.iter().map(|file| finding(file)).collect();
    let artifacts = ScanArtifacts {
        sast: Some(Findings::of(&findings).unwrap()),
        duration: Duration::from_millis(1_000),
        ..ScanArtifacts::default()
    };
    match client.submit(id, &artifacts).await {
        Ok(accepted) => assert!(accepted, "{base} accepted the result of scan {id}"),
        // The Java container's log names the cause a 500 hides; the binary's went to this test's stderr.
        Err(error) => panic!("{base} refused the result of scan {id}: {error:?}\n{}", java_logs()),
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = mysql(database, &format!("select status from t_scan where id = {id}"));
        if status == "completed" {
            return id;
        }
        assert!(Instant::now() < deadline, "scan {id} on {base} stayed {status:?}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// The tail of every Java container of this test still running.
fn java_logs() -> String {
    let names = docker(&["ps", "--filter", "name=p28-java", "--format", "{{.Names}}"]);
    names.lines().map(|name| docker(&["logs", "--tail", "80", name])).collect::<Vec<_>>().join("\n")
}

fn mysql(database: &Container, query: &str) -> String {
    let output = Command::new("docker")
        .args([
            "exec",
            &database.name,
            "mysql",
            "-N",
            "-B",
            "-uvectispire",
            &format!("-p{DB_PASSWORD}"),
            "vectispire",
            "-e",
            query,
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{query}: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// The repository's issues: `file → (id, fingerprint, state)`.
fn issues(database: &Container, repository: i64) -> std::collections::BTreeMap<String, (String, String, String)> {
    mysql(
        database,
        &format!("select file_path, id, fingerprint, state from t_issue where repo_id = {repository} order by id"),
    )
    .lines()
    .map(|line| {
        let cells: Vec<&str> = line.split('\t').collect();
        let [file, id, fingerprint, state] = cells.as_slice() else { panic!("a row of four cells: {line:?}") };
        assert!(!file.is_empty(), "an issue with no file: {line}");
        ((*file).to_owned(), ((*id).to_owned(), (*fingerprint).to_owned(), (*state).to_owned()))
    })
    .collect()
}

#[tokio::test]
async fn the_issues_java_opened_are_the_ones_rust_resolves_and_back() {
    assert!(
        Command::new("docker").arg("info").output().is_ok_and(|output| output.status.success()),
        "Docker is required: this test is the only check that an upgraded installation keeps its backlog"
    );
    let network = Network(unique_name("p28-net"));
    docker(&["network", "create", &network.0]);
    let db = database(&network);
    let http = reqwest::Client::new();

    // ── 1. Java: the account, the agent, the repository, and a scan finding A and B.
    let (java_app, base) = java(&network).await;
    let first = login(&http, &base, BOOTSTRAP_PASSWORD).await;
    call(
        &http,
        &base,
        &first,
        reqwest::Method::POST,
        "/api/v1/auth/change-password",
        Some(json!({"current_password": BOOTSTRAP_PASSWORD, "new_password": ROTATED_PASSWORD})),
    )
    .await;
    let session = login(&http, &base, ROTATED_PASSWORD).await;
    let declared = call(
        &http,
        &base,
        &session,
        reqwest::Method::POST,
        "/api/v1/admin/agents",
        Some(json!({"name": "p28-switch"})),
    )
    .await;
    let api_key = declared["secret"].as_str().unwrap().to_owned();
    let repository = call(
        &http,
        &base,
        &session,
        reqwest::Method::POST,
        "/api/v1/repositories",
        Some(json!({"name": "p28-switch", "url": "https://gitlab.example.org/acme/switch.git", "branch": "main",
                    "scanManualOnly": true})),
    )
    .await["id"]
        .as_i64()
        .unwrap();
    scan(&http, &base, &session, &api_key, repository, &["src/a.py", "src/b.py"], &db).await;
    let by_java = issues(&db, repository);
    assert_eq!(by_java.len(), 2, "Java opened one issue per finding: {by_java:?}");
    assert!(by_java.values().all(|(_, _, state)| state == "open"), "{by_java:?}");
    drop(java_app);

    // ── 2. Rust: A again, B gone, C new.
    // The session Java opened: sign-in is not served by the binary yet, and a session crossing the switch is
    // `cp-access`'s own test.
    let (rust_app, base) = rust(&db).await;
    scan(&http, &base, &session, &api_key, repository, &["src/a.py", "src/c.py"], &db).await;
    let by_rust = issues(&db, repository);
    assert_eq!(by_rust.len(), 3, "A found again by its fingerprint, not twinned: {by_rust:?}");
    assert_eq!(by_rust["src/a.py"], by_java["src/a.py"], "A is Java's row, still open");
    assert_eq!(by_rust["src/b.py"].0, by_java["src/b.py"].0);
    assert_eq!(by_rust["src/b.py"].2, "resolved", "B, not found again, is resolved: {by_rust:?}");
    assert_eq!(by_rust["src/c.py"].2, "open");
    drop(rust_app);

    // ── 3. Java again: A and C, and nothing new.
    let (_java_again, base) = java(&network).await;
    let session = login(&http, &base, ROTATED_PASSWORD).await;
    scan(&http, &base, &session, &api_key, repository, &["src/a.py", "src/c.py"], &db).await;
    let back = issues(&db, repository);
    assert_eq!(back, by_rust, "Java found Rust's C by its fingerprint and changed nothing it wrote: {back:?}");
}
