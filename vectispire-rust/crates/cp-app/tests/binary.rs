//! The binary, run: what an operator sees on the command line, and that a stop is graceful.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BINARY: &str = env!("CARGO_BIN_EXE_vectispire-control-plane");

fn command(variables: &[(&str, &str)]) -> Command {
    let mut command = Command::new(BINARY);
    // Nothing of the developer's own environment leaks in: only what the test sets.
    command.env_clear();
    command.envs(variables.iter().copied());
    command
}

#[test]
fn the_version_and_the_usage_are_printed() {
    let version = command(&[]).arg("--version").output().unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("vectispire-control-plane 2."));
    let help = command(&[]).arg("--help").output().unwrap();
    assert!(String::from_utf8_lossy(&help.stdout).contains("--check-config"));
    let unknown = command(&[]).arg("--frobnicate").output().unwrap();
    assert_eq!(unknown.status.code(), Some(2));
}

#[test]
fn check_config_prints_every_setting_with_its_origin_and_no_secret() {
    let output = command(&[
        ("VECTISPIRE_PORT", "8443"),
        ("VECTISPIRE_DB_PASSWORD", "hunter2"),
        ("ENCRYPTION_KEY", "k3y-material"),
    ])
    .arg("--check-config")
    .output()
    .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("server.port = 8443  [variable VECTISPIRE_PORT]"), "{text}");
    assert!(text.contains("spring.datasource.url = jdbc:mysql://localhost:3306/vectispire  [default]"), "{text}");
    assert!(text.contains("spring.datasource.password = (set)  [variable VECTISPIRE_DB_PASSWORD]"), "{text}");
    assert!(text.contains("vectispire.encryption.key = (set)  [variable ENCRYPTION_KEY]"), "{text}");
    assert!(!text.contains("hunter2") && !text.contains("k3y-material"), "{text}");
    assert!(text.lines().count() > 80, "{} lines", text.lines().count());
}

#[test]
fn check_config_refuses_what_cannot_be_read_and_names_every_problem() {
    let output = command(&[
        ("VECTISPIRE_PORT", "abc"),
        ("VECTISPIRE_SESSION_LIFETIME", "twelve"),
        ("VECTISPIRE_DB_PASSWORD", "hunter2"),
    ])
    .arg("--check-config")
    .output()
    .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let message = String::from_utf8(output.stderr).unwrap();
    assert!(message.starts_with("The configuration cannot be read:"), "{message}");
    assert!(message.contains("server.port") && message.contains("vectispire.session.absolute-lifetime"), "{message}");
    assert!(!message.contains("hunter2"), "{message}");
}

#[test]
fn check_config_refuses_to_start_on_what_would_leave_a_setting_free_to_reach_the_database_or_the_daemon() {
    // The Java control plane refuses to start on a datasource URL it cannot read the hosts of, and on a
    // Docker host it cannot read the daemon's address from: otherwise it cannot keep a settings screen
    // from pointing at them.
    let datasource =
        command(&[("VECTISPIRE_DB_URL", "jdbc:oracle:thin:@h:1521:x")]).arg("--check-config").output().unwrap();
    assert_eq!(datasource.status.code(), Some(1));
    let message = String::from_utf8(datasource.stderr).unwrap();
    assert!(message.starts_with("The datasource URL cannot be read for the hosts it connects to"), "{message}");

    let docker = command(&[("DOCKER_HOST", "ssh://host")]).arg("--check-config").output().unwrap();
    assert_eq!(docker.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&docker.stderr)
            .starts_with("DOCKER_HOST \"ssh://host\" is not a form Vectispire can read"),
        "{}",
        String::from_utf8_lossy(&docker.stderr)
    );
}

#[test]
fn it_serves_until_it_is_told_to_stop_and_then_stops_gracefully() {
    let mut child =
        command(&[("VECTISPIRE_PORT", "3181")]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();

    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let line = lines.next().expect("the process ended before it started").unwrap();
        seen.push(line.clone());
        if line.contains("Started vectispire") {
            break;
        }
        assert!(Instant::now() < deadline, "no start line: {seen:#?}");
    }
    assert!(seen.iter().any(|line| line.contains("[vectispire]")), "{seen:#?}");
    assert!(seen.last().unwrap().contains("on port 3181"), "{seen:#?}");

    // SIGTERM, as a container platform sends it.
    let killed = Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap();
    assert!(killed.success());
    let rest: Vec<String> = lines.map(Result::unwrap).collect();
    let status = child.wait().unwrap();
    assert!(status.success(), "{status:?} after {rest:#?}");
    let all = rest.join("\n");
    assert!(all.contains("Commencing graceful shutdown. Waiting for active requests to complete"), "{all}");
    assert!(all.contains("Graceful shutdown complete"), "{all}");
}

/// A database that accepts connections and never answers — a server hung, a firewall dropping the replies — does not
/// hold the stop. The release of the scheduler's lease, the last step, waited on the pool's 30-second acquire timeout,
/// which is the whole grace period: CI's runner, where the default database address answers that way, saw the process
/// abandoned (exit 1) after "Commencing graceful shutdown".
#[test]
fn a_database_that_does_not_answer_does_not_hold_the_stop() {
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = silent.local_addr().unwrap().port();
    // Accepted and held open, never answered.
    let held = std::thread::spawn(move || silent.incoming().take(64).filter_map(Result::ok).collect::<Vec<_>>());
    let url = format!("jdbc:mysql://127.0.0.1:{port}/vectispire");
    let mut child = command(&[("VECTISPIRE_PORT", "3182"), ("VECTISPIRE_DB_URL", &url)])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let mut seen = Vec::new();
    loop {
        let line = lines.next().expect("the process ended before it started").unwrap();
        seen.push(line.clone());
        if line.contains("Started vectispire") {
            break;
        }
    }

    let stopping = Instant::now();
    let killed = Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap();
    assert!(killed.success());
    let rest: Vec<String> = lines.map(Result::unwrap).collect();
    let status = child.wait().unwrap();
    let took = stopping.elapsed();
    assert!(status.success(), "{status:?} after {took:?}: {rest:#?}");
    assert!(took < Duration::from_secs(20), "the stop took {took:?}: {rest:#?}");
    assert!(rest.iter().any(|line| line.contains("Graceful shutdown complete")), "{rest:#?}");
    drop(held);
}

/// One `GET`, as a scraper or a probe sends it: the status line and the body.
fn get(port: u16, path: &str, authorization: Option<&str>) -> (String, String) {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let header = authorization.map(|value| format!("Authorization: {value}\r\n")).unwrap_or_default();
    write!(stream, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{header}Connection: close\r\n\r\n").unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    let (head, body) = answer.split_once("\r\n\r\n").unwrap_or((&answer, ""));
    (head.lines().next().unwrap_or_default().to_owned(), body.to_owned())
}

/// The binary while it serves; killed if a test fails before it stops it, so no process outlives the run holding its
/// port.
struct Serving {
    child: std::process::Child,
    lines: Option<std::io::Lines<BufReader<std::process::ChildStdout>>>,
}

impl Drop for Serving {
    fn drop(&mut self) {
        if self.lines.is_some() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// The binary, started, once it listens.
fn serving(port: u16, variables: &[(&str, &str)]) -> Serving {
    let mut child = command(variables).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let mut seen = Vec::new();
    loop {
        let Some(line) = lines.next() else {
            let mut stderr = String::new();
            std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut stderr).unwrap();
            panic!("the process ended before it started: {seen:#?}\n{stderr}");
        };
        let line = line.unwrap();
        seen.push(line.clone());
        if line.contains("Started vectispire") {
            break;
        }
    }
    let serving = Serving { child, lines: Some(lines) };
    // The start line is written before the listener binds: wait for it.
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "nothing listens on {port}: {seen:#?}");
        std::thread::sleep(Duration::from_millis(50));
    }
    serving
}

fn stop(mut serving: Serving) {
    let killed = Command::new("kill").args(["-TERM", &serving.child.id().to_string()]).status().unwrap();
    assert!(killed.success());
    let rest: Vec<String> = serving.lines.take().into_iter().flatten().map(Result::unwrap).collect();
    assert!(serving.child.wait().unwrap().success(), "{rest:#?}");
}

const SCRAPE_TOKEN: &str = "binary-test-scrape-token-0123456789abcdef";

/// The actuator is mounted on the binary's router and answers with **no database**: the probe, and the refusals of
/// what needs a credential. The address here refuses every connection, and neither the start nor these wait on it.
#[test]
fn the_actuator_is_mounted_and_its_probe_needs_no_database() {
    let server = serving(
        3183,
        &[
            ("VECTISPIRE_PORT", "3183"),
            ("VECTISPIRE_DB_URL", "jdbc:mysql://127.0.0.1:9/vectispire"),
            ("VECTISPIRE_METRICS_SCRAPE_TOKEN", SCRAPE_TOKEN),
        ],
    );
    let (status, body) = get(3183, "/actuator/health/liveness", None);
    assert!(status.contains(" 200 ") && body.contains("\"status\":\"UP\""), "{status}: {body}");
    for page in ["/actuator/prometheus", "/actuator/encryption", "/actuator/metrics"] {
        let (status, _) = get(3183, page, None);
        assert!(status.contains(" 401 "), "{page}: {status}");
    }
    stop(server);
}

/// The scrape token configured in the environment reads the Prometheus page of the running binary — the gauges from
/// their snapshot, NaN before the first tick — and nothing else. On a database, since a bearer is first looked up as a
/// session, as Java's filter does.
#[test]
fn the_scrape_token_of_the_environment_reads_the_meters_of_the_running_binary() {
    use vectispire_cp_db::Engine;
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let database = runtime.block_on(vectispire_cp_db::testing::TestDatabase::start(Engine::MySql));
    // What this control plane reads of a URL: no driver parameter, TLS when the server offers it.
    let url = database.jdbc_url().split('?').next().unwrap_or_default().to_owned();
    let server = serving(
        3184,
        &[
            ("VECTISPIRE_PORT", "3184"),
            ("VECTISPIRE_DB_URL", &url),
            ("VECTISPIRE_DB_USER", database.username()),
            ("VECTISPIRE_DB_PASSWORD", database.password()),
            ("VECTISPIRE_METRICS_SCRAPE_TOKEN", SCRAPE_TOKEN),
        ],
    );
    let scraper = format!("Bearer {SCRAPE_TOKEN}");
    let (status, page) = get(3184, "/actuator/prometheus", Some(&scraper));
    assert!(status.contains(" 200 "), "{status}: {page}");
    assert!(page.contains("# TYPE vectispire_scans_queued gauge\n"), "{page}");
    assert!(page.contains("vectispire_scans_queued{application=\"vectispire\",kind=\"repository\"} NaN\n"), "{page}");
    for elsewhere in ["/actuator/encryption", "/actuator/metrics", "/api/v1/auth/me"] {
        let (status, _) = get(3184, elsewhere, Some(&scraper));
        assert!(status.contains(" 401 "), "the token opens the Prometheus page alone: {elsewhere} {status}");
    }
    let (status, _) = get(3184, "/actuator/prometheus", Some("Bearer binary-test-scrape-token-0123456789abcdeX"));
    assert!(status.contains(" 401 "), "{status}");
    stop(server);
    drop(database);
}

#[test]
fn a_log_format_it_does_not_know_stops_it_before_it_serves() {
    let output = command(&[("VECTISPIRE_LOG_FORMAT", "xml")]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("VECTISPIRE_LOG_FORMAT"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
