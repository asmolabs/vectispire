//! **The binary, started, runs a scan with its built-in worker** — the check `AGENTS.md` asks for after the built-in
//! worker claimed nothing for as long as it existed, with every test of it green.
//!
//! A migrated MySQL, the test forge serving `team/api.git` over SSH, and the control plane binary started on them with
//! its worker switched on: a pending repository scan has to be claimed, cloned with the host's SSH (an `ssh-agent`
//! holding the forge's deploy key, as `vectispire.scanning.host-ssh` means), scanned by the real syft, gitleaks and
//! checkov images, matched, ingested, and completed — nothing in between is a test double but the matcher, which
//! would otherwise download its database. The matcher is named through `VECTISPIRE_SCANNING_IMAGES_GRYPE`, the
//! property's own variable, which the runner did not read before the 2.10 audit: the finding it prints is the proof
//! the override reached the scan.
//!
//! The same over HTTPS, from a forge whose authority only the runtime's trust bundle names. The same with
//! `vectispire.scanning.host-ssh` off: the clone has to be refused, the agent's key unused.
//!
//! Then an **image**: a pending scan of a container target has to be claimed by the same worker, the image pulled for
//! its platform and exported by the binary itself, inventoried by the real syft from that archive, matched and
//! completed — with only the dependency type examined, since an image has no source for the other analyses.
//!
//! Then a worker whose runner cannot be built: the binary refuses to start, rather than start with a worker that
//! claims nothing.
//!
//! **Docker, `ssh-agent` and `ssh-add` are required, and their absence fails the test.**

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use vectispire_testkit::docker::{Container, docker};
use vectispire_testkit::forge::Forge;

const BINARY: &str = env!("CARGO_BIN_EXE_vectispire-control-plane");
const MYSQL_IMAGE: &str = "mysql:9.4.0@sha256:135bc87cce147c3d28cecb9ad270b814cb52805af7ddeea83bfcaf157d05a6b2";
const PASSWORD: &str = "throwaway-worker-test"; // gitleaks:allow — a test fixture
const KEY: &str = "cmVmZXJlbmNlLXNjYW5uaW5nLWtleS0zMi1ieXRlcyE="; // gitleaks:allow — a test fixture
const FAKE_GRYPE: &str = "vs-rs-worker-fake-grype:1";
const BUSYBOX: &str = "busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e";

/// The matcher, answering its database commands offline and one match — named so that it can only come from here.
const GRYPE: &str = r#"#!/bin/sh
case "$1 $2" in
  "db update")
    mkdir -p "$GRYPE_DB_CACHE_DIR/6" \
      && echo "fake database" > "$GRYPE_DB_CACHE_DIR/6/vulnerability.db" \
      && echo '{}' > "$GRYPE_DB_CACHE_DIR/6/import.json"
    exit $? ;;
  "db status")
    if [ -s "$GRYPE_DB_CACHE_DIR/6/vulnerability.db" ]; then echo '{"valid": true}'; exit 0; fi
    echo '{"valid": false}'; exit 1 ;;
  "db check")
    echo '{"updateAvailable": false}'; exit 0 ;;
esac
echo '{"matches": [{"vulnerability": {"id": "VS-WORKER-PROBE", "severity": "High"}, "artifact": {"name": "probe", "version": "1.0.0"}}]}'
"#;

fn build_the_fake_matcher() {
    let context = tempfile::Builder::new().prefix("vs-rs-worker-grype-").tempdir().unwrap();
    std::fs::write(context.path().join("grype"), GRYPE).unwrap();
    std::fs::write(
        context.path().join("Dockerfile"),
        format!(
            "FROM {BUSYBOX}\nCOPY grype /grype\nRUN chmod 755 /grype && chmod 0755 /tmp\nENTRYPOINT [\"/grype\"]\n"
        ),
    )
    .unwrap();
    docker(&["build", "-q", "-t", FAKE_GRYPE, &context.path().display().to_string()]);
}

struct Database {
    server: Container,
    port: u16,
}

impl Database {
    async fn start() -> Database {
        let server = Container::run(
            "worker-mysql",
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
                "--default-time-zone=+00:00",
            ],
        );
        let deadline = Instant::now() + Duration::from_secs(180);
        while !Command::new("docker")
            .args([
                "exec",
                &server.name,
                "mysqladmin",
                "ping",
                "-h",
                "127.0.0.1",
                "-u",
                "root",
                &format!("-p{PASSWORD}"),
            ])
            .output()
            .is_ok_and(|output| output.status.success())
        {
            assert!(Instant::now() < deadline, "MySQL was never ready");
            std::thread::sleep(Duration::from_millis(500));
        }
        let port = server.host_port("3306/tcp");
        let settings = vectispire_cp_db::settings::DbSettings {
            url: vectispire_cp_db::settings::DatabaseUrl::parse(&format!("jdbc:mysql://127.0.0.1:{port}/vectispire"))
                .unwrap(),
            username: "vectispire".into(),
            password: vectispire_domain::secret::Secret::new(PASSWORD),
            pool: vectispire_cp_db::settings::PoolSettings::default(),
            ca_pem: None,
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        let db = loop {
            match vectispire_cp_db::Db::connect(&settings).await {
                Ok(db) => break db,
                Err(failure) => {
                    assert!(Instant::now() < deadline, "MySQL never answered: {failure}");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        };
        let vectispire_cp_db::Db::MySql(pool) = &db else { unreachable!("a MySQL URL") };
        vectispire_migrate::run(
            &vectispire_migrate::Database::MySql(pool.clone()),
            &vectispire_migrate::Options::default(),
        )
        .await
        .expect("the schema migrates");
        db.close().await;
        Database { server, port }
    }

    fn sql(&self, statement: &str) -> String {
        let output = Command::new("docker")
            .args([
                "exec",
                &self.server.name,
                "mysql",
                "-N",
                "-B",
                "-u",
                "vectispire",
                &format!("-p{PASSWORD}"),
                "vectispire",
                "-e",
                statement,
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{statement}: {}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }
}

/// An `ssh-agent` of the test's own, holding the forge's deploy key — what "the host's SSH" is to the clone.
struct Agent {
    process: Child,
    socket: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl Agent {
    fn holding(key: &str) -> Agent {
        let dir = tempfile::Builder::new().prefix("vs-rs-ssh-").tempdir_in("/tmp").unwrap();
        let socket = dir.path().join("agent.sock");
        let process = Command::new("ssh-agent")
            .args(["-D", "-a", &socket.display().to_string()])
            .stdout(Stdio::null())
            .spawn()
            .expect("ssh-agent is required");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "ssh-agent never opened its socket");
            std::thread::sleep(Duration::from_millis(50));
        }
        let file = dir.path().join("deploy");
        std::fs::write(&file, key).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let added = Command::new("ssh-add").arg(&file).env("SSH_AUTH_SOCK", &socket).output().unwrap();
        assert!(added.status.success(), "ssh-add: {}", String::from_utf8_lossy(&added.stderr));
        Agent { process, socket, _dir: dir }
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.process.kill();
    }
}

struct Started(Child);

impl Drop for Started {
    fn drop(&mut self) {
        let _ = Command::new("kill").arg("-TERM").arg(self.0.id().to_string()).status();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn binary(database: &Database, variables: &[(&str, String)]) -> Command {
    let mut command = Command::new(BINARY);
    command.env_clear();
    for name in ["PATH", "DOCKER_HOST", "TMPDIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .env("VECTISPIRE_DB_URL", format!("jdbc:mysql://127.0.0.1:{}/vectispire", database.port))
        .env("VECTISPIRE_DB_USER", "vectispire")
        .env("VECTISPIRE_DB_PASSWORD", PASSWORD)
        .env("ENCRYPTION_KEY", KEY)
        .env("VECTISPIRE_PORT", free_port().to_string())
        .env("VECTISPIRE_EMBEDDED_WORKER", "true");
    for (name, value) in variables {
        command.env(name, value);
    }
    command
}

/// What became of a scan of the forge's `team/api.git`, which carries no deployment key.
struct Outcome {
    status: String,
    error: String,
    examined: String,
    probe: String,
    said: String,
}

/// How the scanned repository is reached.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Over {
    /// `team/api.git` over SSH.
    Ssh,
    /// `public/api.git` over HTTPS, the forge's certificate signed by a private authority the binary is given.
    Https,
}

/// The forge's repository, scanned by a started binary with an `ssh-agent` holding the forge's key and the forge's host
/// key in its home, `variables` added to its environment.
async fn the_forge_s_repository_scanned(over: Over, variables: &[(&str, String)]) -> Outcome {
    assert!(
        Command::new("docker").arg("info").output().is_ok_and(|output| output.status.success()),
        "this test needs a Docker daemon; it does not skip itself when there is none"
    );
    build_the_fake_matcher();
    let forge = Forge::start();
    let database = Database::start().await;
    let agent = Agent::holding(&forge.deploy_key);

    let home = tempfile::Builder::new().prefix("vs-rs-worker-home-").tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".ssh")).unwrap();
    std::fs::write(
        home.path().join(".ssh/known_hosts"),
        format!("[localhost]:{} {}\n", forge.ssh_port, forge.host_key),
    )
    .unwrap();
    let work = tempfile::Builder::new().prefix("vs-rs-worker-work-").tempdir().unwrap();
    let vulnerabilities = tempfile::Builder::new().prefix("vs-rs-worker-db-").tempdir().unwrap();

    let url = match over {
        Over::Ssh => forge.ssh_url("team/api.git"),
        Over::Https => forge.https_url("public/api.git"),
    };
    let authority = home.path().join("forge-ca.pem");
    std::fs::write(&authority, &forge.ca_pem).unwrap();
    database.sql(&format!("insert into t_repository (url, branch, name) values ('{url}', 'main', 'api')"));
    let repository = database.sql("select max(id) from t_repository");
    database.sql(&format!(
        "insert into t_scan (branch, status, created_at, repo_id, attempts, findings_count, new_issues_count, \
         resolved_issues_count) values ('main', 'pending', utc_timestamp(), {repository}, 0, 0, 0, 0)"
    ));
    let scan = database.sql("select max(id) from t_scan");

    let log = tempfile::NamedTempFile::new().unwrap();
    let mut environment = vec![
        ("VECTISPIRE_WORKER_INTERVAL", "1s".to_owned()),
        ("VECTISPIRE_SCANNING_IMAGES_GRYPE", FAKE_GRYPE.to_owned()),
        ("VECTISPIRE_VULNERABILITY_DB_DIR", vulnerabilities.path().display().to_string()),
        ("VECTISPIRE_WORK_DIR", work.path().display().to_string()),
        ("HOME", home.path().display().to_string()),
        ("SSH_AUTH_SOCK", agent.socket.display().to_string()),
    ];
    if over == Over::Https {
        environment.push(("VECTISPIRE_TLS_CA_BUNDLE", authority.display().to_string()));
    }
    environment.extend(variables.iter().cloned());
    let started = Started(
        binary(&database, &environment).stdout(log.reopen().unwrap()).stderr(log.reopen().unwrap()).spawn().unwrap(),
    );

    let status = ended(&database, &scan, log.path()).await;
    let outcome = Outcome {
        status,
        error: database.sql(&format!("select coalesce(error, '') from t_scan where id = {scan}")),
        examined: database.sql(&format!("select coalesce(examined_types, '') from t_scan where id = {scan}")),
        probe: database
            .sql(&format!("select count(*) from t_finding where scan_id = {scan} and identifier = 'VS-WORKER-PROBE'")),
        said: std::fs::read_to_string(log.path()).unwrap_or_default(),
    };
    drop(started);
    outcome
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_started_binary_s_worker_claims_clones_scans_and_completes_a_repository_scan() {
    let Outcome { status, error, examined, probe, said } = the_forge_s_repository_scanned(Over::Ssh, &[]).await;
    assert_eq!(status, "completed", "error: {error}\nthe binary said:\n{said}");
    for step in ["vulnerability", "secret", "iac"] {
        assert!(examined.contains(step), "{step} examined: {examined}");
    }
    assert_eq!(probe, "1", "the matcher named through the property's own variable ran: {said}");
}

/// **The runtime's trust reaches the clone**: a forge whose certificate a private authority signed is cloned over HTTPS
/// with the bundle `VECTISPIRE_TLS_CA_BUNDLE` names, as the JVM's store is Java's. The worker trusted the compiled-in
/// authorities alone before 2.10 was finished, and such a forge could not be scanned at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forge_behind_a_private_authority_is_cloned_with_the_runtime_s_trust() {
    let Outcome { status, error, examined, said, .. } = the_forge_s_repository_scanned(Over::Https, &[]).await;
    assert_eq!(status, "completed", "error: {error}\nthe binary said:\n{said}");
    assert!(examined.contains("secret"), "the tree was analysed: {examined}");
}

/// `vectispire.scanning.host-ssh: false` — `GitClone.WithoutKey.NONE`: a repository with no deployment key is cloned with
/// no identity, so a private one is refused, **although the host's agent holds a key the forge accepts**. Inside the
/// control plane the host's identity would clone any target anybody adds; the setting is the operator's way to say no.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_host_ssh_off_a_repository_without_a_key_is_refused_rather_than_cloned_with_the_host_s() {
    let Outcome { status, error, probe, said, .. } =
        the_forge_s_repository_scanned(Over::Ssh, &[("VECTISPIRE_HOST_SSH", "false".to_owned())]).await;
    assert_eq!(status, "failed", "error: {error}\nthe binary said:\n{said}");
    assert!(error.contains("requires authentication. Attach an SSH key to this repository."), "{error}");
    assert_eq!(probe, "0", "nothing was scanned: {said}");
}

/// Waits for the scan to end, and says what the binary logged if it never does.
async fn ended(database: &Database, scan: &str, log: &std::path::Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(600);
    loop {
        let status = database.sql(&format!("select status from t_scan where id = {scan}"));
        if status == "completed" || status == "failed" {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "the scan was still {status} after ten minutes; the binary said:\n{}",
            std::fs::read_to_string(log).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_started_binary_s_worker_exports_and_scans_a_container_image() {
    assert!(
        Command::new("docker").arg("info").output().is_ok_and(|output| output.status.success()),
        "this test needs a Docker daemon; it does not skip itself when there is none"
    );
    build_the_fake_matcher();
    let database = Database::start().await;
    let work = tempfile::Builder::new().prefix("vs-rs-worker-work-").tempdir().unwrap();
    let home = tempfile::Builder::new().prefix("vs-rs-worker-home-").tempdir().unwrap();
    let vulnerabilities = tempfile::Builder::new().prefix("vs-rs-worker-db-").tempdir().unwrap();

    // The busybox the fakes are built on, by digest: small, and pulled for its platform from its registry, as an
    // operator's image is. A local tag would prove nothing — the export pulls first, as Java's does.
    let (name, digest) = BUSYBOX.split_once('@').unwrap();
    database.sql(&format!("insert into t_container (image_name, tag) values ('{name}', '{digest}')"));
    let container = database.sql("select max(id) from t_container");
    database.sql(&format!(
        "insert into t_scan (branch, status, created_at, container_id, attempts, findings_count, new_issues_count, \
         resolved_issues_count) values ('{digest}', 'pending', utc_timestamp(), {container}, 0, 0, 0, 0)"
    ));
    let scan = database.sql("select max(id) from t_scan");

    let log = tempfile::NamedTempFile::new().unwrap();
    let started = Started(
        binary(
            &database,
            &[
                ("VECTISPIRE_WORKER_INTERVAL", "1s".to_owned()),
                ("VECTISPIRE_SCANNING_IMAGES_GRYPE", FAKE_GRYPE.to_owned()),
                ("VECTISPIRE_VULNERABILITY_DB_DIR", vulnerabilities.path().display().to_string()),
                ("VECTISPIRE_WORK_DIR", work.path().display().to_string()),
                ("HOME", home.path().display().to_string()),
            ],
        )
        .stdout(log.reopen().unwrap())
        .stderr(log.reopen().unwrap())
        .spawn()
        .unwrap(),
    );

    let status = ended(&database, &scan, log.path()).await;
    let said = || std::fs::read_to_string(log.path()).unwrap_or_default();
    let error = database.sql(&format!("select coalesce(error, '') from t_scan where id = {scan}"));
    assert_eq!(status, "completed", "error: {error}\nthe binary said:\n{}", said());

    // The SBOM is syft's catalogue of the exported archive: the image's own source, not a directory.
    let source = database
        .sql(&format!("select json_unquote(json_extract(sbom, '$.source.type')) from t_scan where id = {scan}"));
    assert_eq!(source, "image", "the SBOM is the archive's: {}", said());
    // **Not checked: the variant.** On Docker's containerd image store the save exports the host's variant whatever
    // the pull fetched — measured 2026-11-15, Docker 29.1 on arm64: `linux/amd64` pulled, `arm64` saved. Java's
    // `saveImageCmd` names no platform either, so this reproduces Java 1.0; the fix belongs to both sides.
    let examined = database.sql(&format!("select examined_types from t_scan where id = {scan}"));
    assert!(examined.contains("vulnerability"), "dependencies examined: {examined}");
    for step in ["secret", "iac", "sast"] {
        assert!(!examined.contains(step), "an image declares no {step} analysis: {examined}");
    }
    let probe = database
        .sql(&format!("select count(*) from t_finding where scan_id = {scan} and identifier = 'VS-WORKER-PROBE'"));
    assert_eq!(probe, "1", "the image's SBOM was matched: {}", said());
    // The archive goes the moment the SBOM is read, and the workspace with the scan.
    let left: Vec<_> = std::fs::read_dir(work.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("vectispire-scan-"))
        .collect();
    assert!(left.is_empty(), "a scan workspace was left behind: {left:?}");
    drop(started);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_whose_runner_cannot_be_built_refuses_the_start() {
    let database = Database::start().await;
    // A file where the work directory should be: the bundled rules cannot be unpacked, so no runner can be built.
    let not_a_directory = tempfile::NamedTempFile::new().unwrap();
    let log = tempfile::NamedTempFile::new().unwrap();
    let mut child = binary(&database, &[("VECTISPIRE_WORK_DIR", not_a_directory.path().display().to_string())])
        .stdin(Stdio::null())
        .stdout(log.reopen().unwrap())
        .stderr(log.reopen().unwrap())
        .spawn()
        .unwrap();
    // **A deadline, not a wait.** A binary that starts anyway serves for ever: waited on, the test would hang the run
    // instead of failing it — which is what a check of this very refusal did, the first time it was broken on purpose.
    let deadline = Instant::now() + Duration::from_secs(90);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let said = std::fs::read_to_string(log.path()).unwrap_or_default();
    let status = status.unwrap_or_else(|| panic!("the binary started with a worker that claims nothing:\n{said}"));
    assert_eq!(status.code(), Some(1), "{said}");
    assert!(said.contains("scan runner could not be built"), "{said}");
}
