//! The built-in worker as the binary composes it: what the agents screen is told, and the images the runner is given.
//! The scan the binary runs end to end is `tests/worker_runs_a_scan.rs`'s.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use vectispire_cp_app::worker::{BuiltInWorker, images, options};
use vectispire_cp_runtime::settings::{ScannerImages, Scanning, Worker};
use vectispire_runner::WithoutKey;

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
    let chosen = images(&configured);
    assert_eq!(chosen.syft, "registry.example/syft:1");
    assert_eq!(chosen.grype, pinned.grype, "blank keeps the pinned digest");
    assert_eq!(chosen.gitleaks, pinned.gitleaks);
}

#[test]
fn host_ssh_and_the_bundled_rules_reach_the_runner() {
    let defaults = options(&scanning());
    assert_eq!(defaults.without_key, WithoutKey::HostSsh);
    assert_eq!(defaults.bundled_rules, None);

    let mut configured = scanning();
    configured.host_ssh = false;
    configured.bundled_rules = Some("/opt/rules".to_owned());
    let chosen = options(&configured);
    assert_eq!(chosen.without_key, WithoutKey::None, "off, a repository with no key is cloned with no identity");
    assert_eq!(chosen.bundled_rules, Some(std::path::PathBuf::from("/opt/rules")));

    configured.bundled_rules = Some("  ".to_owned());
    assert_eq!(options(&configured).bundled_rules, None, "blank unpacks the binary's own");
}
