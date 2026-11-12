//! A real secret scan: the pinned gitleaks image, run by this crate's runner through the socket proxy
//! configured as the composition configures it, over a workspace holding one planted secret.
//!
//! Needs Docker, and fails without it — a suite that skips itself reports green having checked
//! nothing. The planted value is assembled at run time, so the file on disk is the only place it
//! exists and this source never reads as a leak.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use vectispire_container::{ContainerRunner, ScannerLimits};
use vectispire_scanners::{images, secrets};
use vectispire_testkit::docker::docker;
use vectispire_testkit::proxy::SocketProxy;

/// A workspace as the agent lays it out: `source/` cloned, `rules/` copied, 0700.
fn workspace_with_a_planted_key() -> tempfile::TempDir {
    let workspace = tempfile::Builder::new().prefix("vs-rs-scan-").tempdir().unwrap();
    std::fs::set_permissions(workspace.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir_all(workspace.path().join("source/deploy")).unwrap();
    std::fs::create_dir_all(workspace.path().join("rules/gitleaks")).unwrap();
    std::fs::write(workspace.path().join("rules/gitleaks/gitleaks.toml"), "[extend]\nuseDefault = true\n").unwrap();
    // An invented AWS access key id — "AKIA" and sixteen base-32 characters — assembled here.
    let key = ["AKIA", "Q7ZR", "4TMX", "2KDW", "B3PN"].concat();
    std::fs::write(workspace.path().join("source/deploy/app.env"), format!("AWS_ACCESS_KEY_ID={key}\n")).unwrap();
    workspace
}

#[tokio::test(flavor = "multi_thread")]
async fn gitleaks_finds_the_planted_key_through_the_proxy_and_leaves_no_container() {
    let proxy = SocketProxy::start();
    let runner = ContainerRunner::connect(Some(&proxy.address), ScannerLimits::default_for_this_host()).unwrap();
    assert!(runner.is_available().await, "the runner reaches the daemon through the proxy");
    let workspace = workspace_with_a_planted_key();

    let findings = secrets::scan(&runner, workspace.path(), None, images::GITLEAKS).await.unwrap().expect("a report");

    assert!(
        findings
            .iter()
            .any(|finding| finding.rule == "aws-access-token" && finding.file == "deploy/app.env" && finding.line == 1),
        "{findings:?}"
    );
    assert!(!workspace.path().join(secrets::REPORT_FILENAME).exists(), "the report of plaintext secrets is gone");
    let left = docker(&[
        "ps",
        "-a",
        "--filter",
        "label=dev.vectispire.scanner=gitleaks (secret detection)",
        "--filter",
        "status=exited",
        "-q",
    ]);
    assert!(left.is_empty(), "the scanner container was removed: {left}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_container_runs_confined() {
    let proxy = SocketProxy::start();
    let runner = ContainerRunner::connect(Some(&proxy.address), ScannerLimits::default_for_this_host()).unwrap();
    let workspace = workspace_with_a_planted_key();
    // The holder image of the bounded outputs, busybox-based, asked what the kernel gave it.
    let mut run = vectispire_container::ContainerRun::new(
        "busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e",
        vec![
            "sh".into(),
            "-c".into(),
            "id -u; grep CapEff /proc/self/status; touch /root-write 2>&1 || echo ro; ip link 2>/dev/null | grep -c ': ' ; cat /sys/fs/cgroup/pids.max 2>/dev/null || true".into(),
        ],
        vec![],
        "rust confinement probe",
    );
    run.user = Some("1000:1000".into());
    let result = runner.run(&run).await.unwrap();
    let lines: Vec<&str> = result.stdout.lines().collect();
    assert_eq!(lines.first(), Some(&"1000"), "{}", result.stdout);
    assert!(result.stdout.contains("CapEff:\t0000000000000000"), "no capability: {}", result.stdout);
    assert!(result.stdout.contains("Read-only file system") || result.stdout.contains("ro"), "{}", result.stdout);
    assert!(result.stdout.contains("\n512"), "the pids limit: {}", result.stdout);
    drop(workspace);
}
