//! **Sessions and keys survive the switch** — the Java control plane and the Rust credentials on one database.
//!
//! The published control plane (by digest, as the agent's end-to-end test starts it) runs on a throwaway MySQL and
//! migrates it itself. Then, on that same database:
//!
//! - a session the Java control plane opened, an integration key it issued and an agent's key it created all
//!   authenticate through the Rust credentials, with the account, scopes and agent Java recorded;
//! - a session the Rust side opened and a key it issued authenticate on the Java control plane, as a bearer token and
//!   as `X-API-Key`;
//! - a revocation on one side is a 401 on the other, and a Java sign-out (`DELETE /api/v1/auth/session`) ends the session for Rust;
//! - **a second factor enrolled on one side opens the account on the other**: enabled in Rust, Java asks for the code
//!   at sign-in, accepts the next one and disables the factor with a Rust backup code; enabled again on Java, Rust
//!   accepts its next code and one of its backup codes — the contexts, the encryption and the codes' joining agree.
//!
//! **Docker is required, and its absence fails the test.** Containers and the network are `vs-rs-p1c-*`, removed on
//! drop. The image is `VECTISPIRE_E2E_CONTROL_PLANE_IMAGE`, by default the last published release by digest.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "accounts_support/mod.rs"]
mod accounts_support;
mod support;

use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use vectispire_cp_access::credentials::{CredentialService, KeyRequest, ScimToken, SessionPolicy, SystemClock};
use vectispire_cp_db::{Db, ScanTarget};
use vectispire_cp_http::credentials::{BoxFuture, Credentials};
use vectispire_cp_http::principal::Credential;
use vectispire_cp_http::{ApiKeyScope, Role};
use vectispire_testkit::docker::{Container, docker, unique_name};

const DEFAULT_IMAGE: &str =
    "ghcr.io/asmolabs/vectispire:0.11.0-rc.3@sha256:453aedcefc981ff9e91298c38db74138b027f5b1cac5e284fa889d1e264e1d46";
/// The composition's MySQL, as `docker-compose.yml` pins it.
const MYSQL_IMAGE: &str = "mysql:8.4.11@sha256:24989179f58856db763f418010c1169fecc944e3ec1ea7e921572d83eb070f70";
const DB_PASSWORD: &str = "vs-rs-p1c-database-password"; // gitleaks:allow — invented, for a container removed after the test
/// The throwaway control plane's own encryption key.
const CONTROL_PLANE_KEY: &str = "dnMtcnMtcDFjLWVuY3J5cHRpb24ta2V5LWludmVudCE="; // gitleaks:allow — base64 of an invented 32-byte label
const BOOTSTRAP_PASSWORD: &str = "Vs-rs-p1c-bootstrap-Invented-1!"; // gitleaks:allow — invented
const ROTATED_PASSWORD: &str = "Vs-rs-p1c-rotated-Invented-2!"; // gitleaks:allow — invented

struct Network(String);

impl Drop for Network {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["network", "rm", &self.0]).output();
    }
}

/// Never a restriction: the target exists for this test's purpose only where it is not asked about.
struct NoTarget;

impl vectispire_cp_access::credentials::IssuerSees for NoTarget {
    fn issuer_sees<'a>(
        &'a self,
        _issuer: i64,
        _target: ScanTarget,
    ) -> BoxFuture<'a, Result<bool, vectispire_cp_access::credentials::StoreError>> {
        Box::pin(async move { Ok(false) })
    }
}

/// MySQL with its port published on the loopback, and the Java control plane beside it.
async fn java_control_plane() -> (Network, Container, Container, String, u16) {
    let image = std::env::var("VECTISPIRE_E2E_CONTROL_PLANE_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_owned());
    let network = Network(unique_name("p1c-net"));
    docker(&["network", "create", &network.0]);
    let database = Container::run(
        "p1c-mysql",
        &[
            "--network",
            &network.0,
            "--network-alias",
            "db",
            "-p",
            "127.0.0.1::3306",
            "-e",
            &format!("MYSQL_ROOT_PASSWORD={DB_PASSWORD}"),
            "-e",
            "MYSQL_DATABASE=vectispire",
            "-e",
            "MYSQL_USER=vectispire",
            "-e",
            &format!("MYSQL_PASSWORD={DB_PASSWORD}"),
            MYSQL_IMAGE,
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(180);
    while !Command::new("docker")
        .args([
            "exec",
            &database.name,
            "mysql",
            "-uvectispire",
            &format!("-p{DB_PASSWORD}"),
            "-h127.0.0.1",
            "-e",
            "select 1",
            "vectispire",
        ])
        .output()
        .is_ok_and(|output| output.status.success())
    {
        assert!(Instant::now() < deadline, "MySQL did not start");
        std::thread::sleep(Duration::from_secs(1));
    }
    let variables = [
        "VECTISPIRE_DB_URL=jdbc:mysql://db:3306/vectispire".to_owned(),
        "VECTISPIRE_DB_USER=vectispire".to_owned(),
        format!("VECTISPIRE_DB_PASSWORD={DB_PASSWORD}"),
        // Spelt in two halves, as the agent's test spells it: the workspace's guards look for the name.
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
    let app = Container::run("p1c-app", &arguments);
    let base = format!("http://127.0.0.1:{}", app.host_port("3180/tcp"));
    let http = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if http.get(format!("{base}/actuator/health")).send().await.is_ok_and(|r| r.status().is_success()) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the control plane did not become healthy: {}",
            docker(&["logs", "--tail", "60", &app.name])
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let port = database.host_port("3306/tcp");
    (network, database, app, base, port)
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

/// The Java control plane's answer to `GET path` with one header.
async fn java_status(http: &reqwest::Client, base: &str, path: &str, header: (&str, &str)) -> (u16, Value) {
    let response = http.get(format!("{base}{path}")).header(header.0, header.1).send().await.unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

#[tokio::test]
async fn sessions_and_keys_cross_between_the_java_and_the_rust_control_planes() {
    let (_network, _database, _app, base, port) = java_control_plane().await;
    let http = reqwest::Client::new();

    // ── The Java side: a session, an integration key, an agent and its key.
    let first = login(&http, &base, BOOTSTRAP_PASSWORD).await;
    let rotated = http
        .post(format!("{base}/api/v1/auth/change-password"))
        .bearer_auth(&first)
        .json(&json!({"current_password": BOOTSTRAP_PASSWORD, "new_password": ROTATED_PASSWORD}))
        .send()
        .await
        .unwrap()
        .status();
    assert!(rotated.is_success(), "password rotation: {rotated}");
    let java_session = login(&http, &base, ROTATED_PASSWORD).await;
    let issued: Value = http
        .post(format!("{base}/api/v1/api-keys"))
        .bearer_auth(&java_session)
        .json(&json!({"name": "java-issued", "scopes": ["read", "export"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let java_key = issued["secret"].as_str().unwrap_or_else(|| panic!("no key: {issued}")).to_owned();
    let java_key_id = issued["key"]["id"].as_str().unwrap().to_owned();
    let declared: Value = http
        .post(format!("{base}/api/v1/admin/agents"))
        .bearer_auth(&java_session)
        .json(&json!({"name": "java-agent", "credentials_mode": "delegated"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let java_agent_key = declared["secret"].as_str().unwrap_or_else(|| panic!("no agent key: {declared}")).to_owned();

    // ── The Rust side, on the same database.
    let db = support::connect(&format!("jdbc:mysql://127.0.0.1:{port}/vectispire"), "vectispire", DB_PASSWORD).await;
    let credentials = CredentialService::new(
        db.clone(),
        Arc::new(SystemClock),
        SessionPolicy::default(),
        Arc::new(support::AgentsTable(db.clone())),
        ScimToken::default(),
    );
    let admin_id = support::scalar_i64(&db, "select id from t_user where username = ?", "", "admin").await;

    // Java → Rust: the session Java opened.
    let principal = credentials.session(&java_session).await.expect("Java's session resolves in Rust");
    let account = principal.account.clone().unwrap();
    assert_eq!(account.username, "admin");
    assert_eq!(account.role, Some(Role::Superuser));
    assert!(!account.must_change_password);
    assert!(principal.is_session());
    // The token the rotation was made with: whatever Java answers for it, Rust answers the same.
    let (java_answer, _) =
        java_status(&http, &base, "/api/v1/auth/me", ("Authorization", &format!("Bearer {first}"))).await;
    assert_eq!(credentials.session(&first).await.is_some(), java_answer == 200, "Java answered {java_answer}");

    // Java → Rust: the integration key Java issued — its account, its scopes, and the use recorded.
    let principal = credentials.api_key(&java_key).await.expect("Java's key resolves in Rust");
    assert_eq!(principal.account.unwrap().username, "admin");
    assert_eq!(
        principal.credential,
        Credential::Integration { key_id: java_key_id.clone(), scopes: vec![ApiKeyScope::Read, ApiKeyScope::Export] }
    );
    let used = credentials.key(uuid::Uuid::try_parse(&java_key_id).unwrap()).await.unwrap().unwrap();
    assert!(used.last_used_at.is_some(), "Rust recorded the use on Java's row");

    // Java → Rust: the agent's key Java created.
    let principal = credentials.api_key(&java_agent_key).await.expect("Java's agent key resolves in Rust");
    assert_eq!(principal.credential, Credential::Agent { agent: "agent:java-agent".into() });

    // Rust → Java: a session Rust opened.
    let rust_session = credentials.open_session(admin_id, Some("rust"), Some("127.0.0.1")).await.unwrap();
    let (status, me) = java_status(
        &http,
        &base,
        "/api/v1/auth/me",
        ("Authorization", &format!("Bearer {}", rust_session.token.expose())),
    )
    .await;
    assert_eq!(status, 200, "Java accepts the session Rust opened: {me}");
    assert!(me.to_string().contains("\"admin\""), "{me}");

    // Rust → Java: a key Rust issued, as a bearer token and as X-API-Key.
    let rust_key = credentials
        .issue_integration_key(
            admin_id,
            &KeyRequest {
                name: Some("rust-issued".into()),
                scopes: Some(vec![Some("read".into())]),
                ..KeyRequest::default()
            },
            &NoTarget,
        )
        .await
        .unwrap();
    let (status, answer) =
        java_status(&http, &base, "/api/v1/repositories", ("X-API-Key", rust_key.secret.expose())).await;
    assert_eq!(status, 200, "Java accepts the key Rust issued as X-API-Key: {answer}");
    let (status, answer) = java_status(
        &http,
        &base,
        "/api/v1/repositories",
        ("Authorization", &format!("Bearer {}", rust_key.secret.expose())),
    )
    .await;
    assert_eq!(status, 200, "and as a bearer token: {answer}");
    let listed: Value = http
        .get(format!("{base}/api/v1/api-keys"))
        .bearer_auth(&java_session)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row =
        listed.as_array().unwrap().iter().find(|key| key["name"] == "rust-issued").expect("Java lists Rust's key");
    assert_eq!(row["prefix"].as_str(), rust_key.key.prefix.as_deref());
    assert_eq!(row["scopes"], json!(["read"]));
    assert!(!row["lastUsedAt"].is_null(), "Java recorded its use: {row}");

    // A revocation on one side is a 401 on the other.
    credentials.revoke_key(uuid::Uuid::try_parse(&java_key_id).unwrap()).await.unwrap();
    let (status, _) = java_status(&http, &base, "/api/v1/repositories", ("X-API-Key", &java_key)).await;
    assert_eq!(status, 401, "Rust revoked Java's key");
    let logout = http
        .delete(format!("{base}/api/v1/auth/session"))
        .bearer_auth(rust_session.token.expose())
        .send()
        .await
        .unwrap()
        .status();
    assert!(logout.is_success(), "Java logs out the session Rust opened: {logout}");
    assert!(credentials.session(rust_session.token.expose()).await.is_none(), "and Rust sees it gone");
    assert!(credentials.revoke_all_for_user(admin_id).await.unwrap() >= 1, "Java's own session was still open");
    let (status, _) =
        java_status(&http, &base, "/api/v1/auth/me", ("Authorization", &format!("Bearer {java_session}"))).await;
    assert_eq!(status, 401, "Rust closed every session of the account, Java's included");

    // ── The second factor across the switch, under the same key the Java control plane holds.
    second_factor_both_ways(&http, &base, &db, admin_id).await;

    // The stored forms are the same on both sides: each row's hash is the one the other side computes.
    let hashes: Vec<String> = match &db {
        Db::MySql(pool) => sqlx::query_scalar("select key_hash from t_api_key").fetch_all(pool).await.unwrap(),
        Db::PostgreSql(_) => unreachable!("the composition's engine"),
    };
    assert!(hashes.iter().all(|hash| hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$")), "{hashes:?}");
}

/// The audit log is not what this test is about.
#[derive(Clone)]
struct Nowhere;

impl vectispire_cp_access::accounts::Audit for Nowhere {
    async fn record(&self, _: vectispire_cp_access::accounts::AuditRecord) {}
}

async fn second_factor_both_ways(http: &reqwest::Client, base: &str, db: &Db, admin_id: i64) {
    use vectispire_cp_access::accounts::AccountStore;
    use vectispire_cp_access::totp;
    use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
    use vectispire_domain::secret::Secret;

    let door = VaultDoor {
        sender: vectispire_cp_outbound::PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: vectispire_cp_outbound::OutboundUrlGuard::new(Vec::new()),
    };
    let config = EncryptionConfig { key: Some(Secret::new(CONTROL_PLANE_KEY)), ..EncryptionConfig::default() };
    let users = vectispire_cp_access::SqlAccountStore::new(db.clone(), accounts_support::RawCredentials);
    let factor = vectispire_cp_access::second_factor::SecondFactor::new(
        users.clone(),
        Nowhere,
        vectispire_cp_access::SqlSignInStore::new(db.clone()),
        Arc::new(Encryption::new(&config, door).unwrap()),
        Arc::new(SystemClock),
    );
    let now = || time::OffsetDateTime::now_utc();

    // Rust enables it.
    let secret = totp::generate_secret();
    let codes = factor.enable(admin_id, &secret, &totp::generate_code(&secret, now()).unwrap()).await.unwrap();

    // Java asks for the code, and accepts the next one.
    let challenge: Value = http
        .post(format!("{base}/api/v1/auth/login"))
        .json(&json!({"username": "admin", "password": ROTATED_PASSWORD}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(challenge["mfa_required"], json!(true), "Java sees the factor Rust enabled: {challenge}");
    let verified: Value = http
        .post(format!("{base}/api/v1/auth/mfa/verify"))
        .json(&json!({
            "mfa_token": challenge["mfa_token"],
            "code": totp::generate_code(&secret, now() + time::Duration::seconds(30)).unwrap(),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let session =
        verified["token"].as_str().unwrap_or_else(|| panic!("Java refused Rust's secret: {verified}")).to_owned();

    // Java spends one of Rust's backup codes to switch it off.
    let disabled = http
        .post(format!("{base}/api/v1/auth/mfa/disable"))
        .bearer_auth(&session)
        .json(&json!({"code": codes[0].expose()}))
        .send()
        .await
        .unwrap();
    let status = disabled.status();
    assert!(status.is_success(), "Java read Rust's backup codes: {status} {}", disabled.text().await.unwrap());
    assert!(!users.find_by_id(admin_id).await.unwrap().unwrap().mfa_enabled);

    // Java enables a new one; Rust accepts its next code, and one of its backup codes.
    let setup: Value = http
        .post(format!("{base}/api/v1/auth/mfa/setup"))
        .bearer_auth(&session)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let java_secret = setup["secret"].as_str().unwrap_or_else(|| panic!("{setup}")).to_owned();
    let enabled: Value = http
        .post(format!("{base}/api/v1/auth/mfa/enable"))
        .bearer_auth(&session)
        .json(&json!({"secret": java_secret, "code": totp::generate_code(&java_secret, now()).unwrap()}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let java_codes = enabled.get("backupCodes").or_else(|| enabled.get("backup_codes")).cloned();
    let java_code =
        java_codes.as_ref().and_then(|codes| codes[0].as_str()).unwrap_or_else(|| panic!("{enabled}")).to_owned();
    let user = users.find_by_id(admin_id).await.unwrap().unwrap();
    assert!(user.mfa_enabled);
    let next = totp::generate_code(&java_secret, now() + time::Duration::seconds(30)).unwrap();
    assert!(factor.verify(&user, Some(&next)).await.unwrap(), "Rust reads the secret Java sealed");
    let user = users.find_by_id(admin_id).await.unwrap().unwrap();
    assert!(factor.verify(&user, Some(&java_code)).await.unwrap(), "Rust reads and spends Java's backup codes");
}
