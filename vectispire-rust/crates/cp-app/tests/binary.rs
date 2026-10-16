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
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("vectispire-control-plane 0."));
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
