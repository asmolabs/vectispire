//! Accounts against the **real Java control plane** — the published 0.11.0-rc.3 image on a throwaway MySQL, the
//! two programs on one database, each signing in with what the other wrote.
//!
//! - Java → Rust: the bootstrap account and an account created through Java's `/api/v1/users` verify here, flags
//!   and role as Java stored them.
//! - Rust → Java: an account this crate created signs in through Java's `/auth/login` and changes its password
//!   there (Java verified the Rust hash twice); a Rust password reset is the password Java accepts next; a weaker
//!   hash written here is rewritten by Java's sign-in and still verifies here; a lift of the password-change
//!   requirement done here discards the password Java would have accepted.
//!
//! **Docker is required, and its absence fails the test.** Containers and the network are `vs-rs-accj-*`, removed
//! on drop. `VECTISPIRE_E2E_CONTROL_PLANE_IMAGE` overrides the image.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use time::OffsetDateTime;
use vectispire_cp_access::SqlAccountStore;
use vectispire_cp_access::accounts::{
    AccountChange, AccountStore, Accounts, Audit, AuditRecord, Clock, NewAccount, PasswordHash, RequestActor,
};
use vectispire_cp_access::passwords;
use vectispire_cp_db::Db;
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_domain::secret::Secret;
use vectispire_testkit::docker::{Container, docker, unique_name};

mod support;

const DEFAULT_IMAGE: &str =
    "ghcr.io/asmolabs/vectispire:0.11.0-rc.3@sha256:453aedcefc981ff9e91298c38db74138b027f5b1cac5e284fa889d1e264e1d46";
const MYSQL_IMAGE: &str = "mysql:8.4.11@sha256:24989179f58856db763f418010c1169fecc944e3ec1ea7e921572d83eb070f70";
// Invented, for a throwaway database and control plane, and never anything else's.
const DB_PASSWORD: &str = "vs-rs-accj-database-password"; // gitleaks:allow
const CONTROL_PLANE_KEY: &str = "dnMtcnMtYWNjai1lbmNyeXB0aW9uLWtleS1pbnZlbnQ="; // gitleaks:allow — base64 of an invented label
const BOOTSTRAP: &str = "Vs-rs-accj-bootstrap-Invented-1!";
const ROTATED: &str = "Vs-rs-accj-rotated-Invented-2!";
const JUNO: &str = "Juno-Invented-Passphrase-3"; // gitleaks:allow — invented, for an account in a container removed after the test

struct Network(String);
impl Drop for Network {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["network", "rm", &self.0]).output();
    }
}

struct Now;
impl Clock for Now {
    fn now(&self) -> OffsetDateTime {
        vectispire_cp_db::types::now()
    }
}

struct Nowhere;
impl Audit for Nowhere {
    async fn record(&self, _record: AuditRecord) {}
}

async fn login(http: &reqwest::Client, base: &str, username: &str, password: &str) -> (u16, Value) {
    let response = http
        .post(format!("{base}/api/v1/auth/login"))
        .json(&json!({"username": username, "password": password}))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

async fn token(http: &reqwest::Client, base: &str, username: &str, password: &str) -> String {
    let (status, answer) = login(http, base, username, password).await;
    assert_eq!(status, 200, "{username}: {answer}");
    answer["token"].as_str().unwrap().to_owned()
}

async fn change_password(http: &reqwest::Client, base: &str, token: &str, current: &str, new: &str) -> u16 {
    http.post(format!("{base}/api/v1/auth/change-password"))
        .bearer_auth(token)
        .json(&json!({"current_password": current, "new_password": new}))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn accounts_written_by_either_program_sign_in_on_the_other() {
    let image = std::env::var("VECTISPIRE_E2E_CONTROL_PLANE_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_owned());
    let network = Network(unique_name("accj-net"));
    docker(&["network", "create", &network.0]);
    let database = Container::run(
        "accj-mysql",
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
            "--default-time-zone=+00:00",
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
        format!("{}={CONTROL_PLANE_KEY}", ["ENCRYPTION", "_KEY"].concat()),
        "VECTISPIRE_BOOTSTRAP_USERNAME=admin".to_owned(),
        format!("VECTISPIRE_BOOTSTRAP_PASSWORD={BOOTSTRAP}"),
        "VECTISPIRE_EMBEDDED_WORKER=false".to_owned(),
    ];
    let mut arguments = vec!["--network", network.0.as_str(), "-p", "127.0.0.1::3180"];
    for variable in &variables {
        arguments.extend(["-e", variable.as_str()]);
    }
    arguments.push(image.as_str());
    let app = Container::run("accj-app", &arguments);
    let base = format!("http://127.0.0.1:{}", app.host_port("3180/tcp"));
    let http = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(300);
    while !http.get(format!("{base}/actuator/health")).send().await.is_ok_and(|r| r.status().is_success()) {
        assert!(
            Instant::now() < deadline,
            "the control plane did not start: {}",
            docker(&["logs", "--tail", "60", &app.name])
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    let settings = DbSettings {
        url: DatabaseUrl::parse(&format!("jdbc:mysql://127.0.0.1:{}/vectispire", database.host_port("3306/tcp")))
            .unwrap(),
        username: "vectispire".into(),
        password: Secret::new(DB_PASSWORD),
        pool: PoolSettings { max_connections: 4, min_connections: 1, ..PoolSettings::default() },
        ca_pem: None,
    };
    let db = Db::connect(&settings).await.unwrap();
    let store = SqlAccountStore::new(db.clone(), support::RawCredentials);
    let accounts = Accounts::new(SqlAccountStore::new(db.clone(), support::RawCredentials), Nowhere, Now);

    // ── Java → Rust: the bootstrap account, its Java-made hash and its flag.
    let bootstrap =
        accounts.check_sign_in_password(Some("admin"), Some(BOOTSTRAP)).await.unwrap().expect("Java's hash");
    assert_eq!(bootstrap.role, "SUPERUSER");
    assert!(bootstrap.must_change_password, "the bootstrap account owes a change");
    assert!(accounts.check_sign_in_password(Some("admin"), Some(ROTATED)).await.unwrap().is_none());

    let first = token(&http, &base, "admin", BOOTSTRAP).await;
    assert_eq!(change_password(&http, &base, &first, BOOTSTRAP, ROTATED).await, 200);
    let admin = token(&http, &base, "admin", ROTATED).await;
    let created = http
        .post(format!("{base}/api/v1/users"))
        .bearer_auth(&admin)
        .json(&json!({"username": "juno", "password": JUNO, "role": "ADMIN", "email": "juno@example.org"}))
        .send()
        .await
        .unwrap();
    assert!(created.status().is_success(), "{}", created.text().await.unwrap());
    let juno = store.find_by_username("juno").await.unwrap().expect("the account Java created");
    assert_eq!(
        (juno.role.as_str(), juno.email.as_deref(), juno.must_change_password),
        ("ADMIN", Some("juno@example.org"), true)
    );
    assert!(passwords::verify(Some(JUNO), juno.password.as_ref().map(PasswordHash::encoded)));
    assert!(!passwords::needs_rehash(juno.password.as_ref().map(PasswordHash::encoded)));
    let rotated = store.find_by_username("admin").await.unwrap().unwrap();
    assert!(!rotated.must_change_password, "Java's own password change cleared the flag");
    assert!(passwords::verify(Some(ROTATED), rotated.password.as_ref().map(PasswordHash::encoded)));

    // ── Rust → Java: an account created here signs in there, owes a change there, and changes it there.
    let actor = RequestActor::default();
    let rusty = accounts
        .create(
            NewAccount {
                username: Some("rusty".to_owned()),
                password: Some(Secret::new("Rusty-Invented-Passphrase-4")),
                role: Some("ciso".to_owned()),
                ..NewAccount::default()
            },
            Some(rotated.id),
            &actor,
        )
        .await
        .unwrap();
    let (status, answer) = login(&http, &base, "rusty", "Rusty-Invented-Passphrase-4").await;
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["user"]["role"], "CISO");
    assert_eq!(answer["user"]["mustChangePassword"], true);
    let rusty_token = answer["token"].as_str().unwrap().to_owned();
    assert_eq!(
        change_password(&http, &base, &rusty_token, "Rusty-Invented-Passphrase-4", "Rusty-Invented-Passphrase-5").await,
        200
    );
    assert!(
        accounts.check_sign_in_password(Some("rusty"), Some("Rusty-Invented-Passphrase-5")).await.unwrap().is_some()
    );

    // A reset done here is the password Java accepts next, and the flag Java holds the account on.
    accounts
        .update(
            rusty.user.id,
            AccountChange { password: Some(Secret::new("Rusty-Reset-Invented-6")), ..AccountChange::default() },
            Some(rotated.id),
            &actor,
        )
        .await
        .unwrap();
    assert_eq!(login(&http, &base, "rusty", "Rusty-Invented-Passphrase-5").await.0, 401);
    let (status, answer) = login(&http, &base, "rusty", "Rusty-Reset-Invented-6").await;
    assert_eq!((status, answer["user"]["mustChangePassword"].as_bool()), (200, Some(true)));

    // A weaker hash written here is verified by Java's sign-in, which rewrites it under today's cost.
    let weaker = PasswordHash::new(passwords::hash_with(JUNO, 4096, 1, 1).unwrap());
    store.rehash(juno.id, weaker.clone()).await.unwrap();
    assert_eq!(login(&http, &base, "juno", JUNO).await.0, 200);
    let rewritten = store.find_by_id(juno.id).await.unwrap().unwrap().password.unwrap();
    assert_ne!(rewritten, weaker, "Java rewrote it");
    assert!(!passwords::needs_rehash(Some(rewritten.encoded())));
    assert!(passwords::verify(Some(JUNO), Some(rewritten.encoded())));

    // A lift done here discards the password Java would have accepted.
    let reset = accounts
        .update(
            juno.id,
            AccountChange { password: Some(Secret::new("Juno-Reset-Invented-7")), ..AccountChange::default() },
            Some(rotated.id),
            &actor,
        )
        .await
        .unwrap();
    assert!(reset.user.must_change_password);
    let mut bound = store.find_by_id(juno.id).await.unwrap().unwrap();
    bound.keycloak_id = Some("subject-juno".to_owned());
    store.save(&bound, false).await.unwrap();
    assert_eq!(login(&http, &base, "juno", "Juno-Reset-Invented-7").await.0, 200, "before the lift");
    accounts.clear_password_change_requirement(juno.id, Some(rotated.id), &actor).await.unwrap();
    assert_eq!(login(&http, &base, "juno", "Juno-Reset-Invented-7").await.0, 401, "after the lift");

    // Java's own list shows the Rust-made account as Rust wrote it.
    let listed: Value =
        http.get(format!("{base}/api/v1/users")).bearer_auth(&admin).send().await.unwrap().json().await.unwrap();
    let rows = listed.as_array().cloned().or_else(|| listed["users"].as_array().cloned()).unwrap_or_default();
    let row = rows.iter().find(|row| row["username"] == "rusty").unwrap_or_else(|| panic!("{listed}"));
    assert_eq!(row["role"], "CISO");
    db.close().await;
    drop(app);
    drop(database);
}
