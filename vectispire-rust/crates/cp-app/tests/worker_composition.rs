//! The built-in worker as the binary composes it: what the agents screen is told, and the images the runner is given.
//! The scan the binary runs end to end is `tests/worker_runs_a_scan.rs`'s.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use vectispire_cp_app::worker::{BuiltInWorker, images};
use vectispire_cp_runtime::settings::{ScannerImages, Scanning, Worker};

fn worker(enabled: bool, labels: &str) -> Worker {
    Worker { enabled, max_concurrent: 2, labels: labels.to_owned(), interval: Duration::from_secs(15) }
}

fn scanning() -> Scanning {
    Scanning {
        image_platform: None,
        host_ssh: true,
        vulnerability_db_dir: None,
        images: ScannerImages { syft: None, grype: None, gitleaks: None, checkov: None, semgrep: None },
        plugin_registry: None,
        plugin_signature_required: true,
        bundled_rules: None,
    }
}

#[test]
fn the_worker_runs_only_when_switched_on_with_a_runner_and_serves_its_labels_only_then() {
    assert_eq!(
        BuiltInWorker::of(&worker(true, "linux, gpu"), true),
        BuiltInWorker { runs: true, labels: vec!["linux".to_owned(), "gpu".to_owned()] }
    );
    assert_eq!(BuiltInWorker::of(&worker(true, "linux"), false), BuiltInWorker { runs: false, labels: Vec::new() });
    assert_eq!(BuiltInWorker::of(&worker(false, "linux"), true), BuiltInWorker { runs: false, labels: Vec::new() });
}

#[test]
fn the_images_are_the_settings_and_blank_keeps_the_pin() {
    let pinned = vectispire_runner::Images::from_lookup(|_| None);
    let mut configured = scanning();
    configured.images.syft = Some(" registry.example/syft:1 ".to_owned());
    configured.images.grype = Some("   ".to_owned());
    let chosen = images(&configured).unwrap();
    assert_eq!(chosen.syft, "registry.example/syft:1");
    assert_eq!(chosen.grype, pinned.grype, "blank keeps the pinned digest");
    assert_eq!(chosen.gitleaks, pinned.gitleaks);
}

#[test]
fn what_the_runner_cannot_honour_is_refused() {
    let mut no_host_ssh = scanning();
    no_host_ssh.host_ssh = false;
    assert!(images(&no_host_ssh).unwrap_err().contains("host-ssh"));
    let mut bundled = scanning();
    bundled.bundled_rules = Some("/opt/rules".to_owned());
    assert!(images(&bundled).unwrap_err().contains("bundled-rules"));
}
