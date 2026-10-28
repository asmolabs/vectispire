//! The built-in worker as the control plane composes it: the runner's settings, and what the agents screen is told of
//! the worker — here rather than inline in `main`, so that `tests/worker_composition.rs` holds them.
//!
//! **Three defects, each invisible to every test of the worker** (2.10 audit, 2026-10-22):
//!
//! - The administration service was handed "the worker runs nothing and serves no label" whatever the configuration
//!   said. Java asks `BuiltInWorker.runs()` — switched on *and* a runner — so with the worker on, the credentialed backlog
//!   and the labels nobody serves reported its own scans as waiting for ever.
//! - The runner read the scanner images straight from the process's variables (`VECTISPIRE_IMAGE_SYFT`). That is the
//!   variable `application.yaml` names, but not every way the control plane is configured: the property's own variable
//!   (`VECTISPIRE_SCANNING_IMAGES_SYFT`) and a file under `/run/secrets` were ignored, and the pinned image ran instead —
//!   the outcome Java's `ScanningConfiguration` names the images one by one to prevent. They are read from the settings
//!   now, with every source the runtime resolves. `host-ssh` and `bundled-rules` were not read at all.
//! - A runner that could not be built was a warning, and the binary started with a worker that claims nothing.

use vectispire_cp_runtime::settings::{ScannerImages, Scanning, Worker};
use vectispire_runner::Images;

/// `BuiltInWorker`: whether the worker claims anything, and the labels it serves — none when it does not run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltInWorker {
    pub runs: bool,
    pub labels: Vec<String>,
}

impl BuiltInWorker {
    /// Switched on, and able to run a scan here (the dispatcher has a runner): the one case in which it claims.
    #[must_use]
    pub fn of(worker: &Worker, runs_scans_here: bool) -> BuiltInWorker {
        let runs = worker.enabled && runs_scans_here;
        let labels = if runs { vectispire_domain::agent_labels::parse(Some(&worker.labels)) } else { Vec::new() };
        BuiltInWorker { runs, labels }
    }
}

/// The images the built-in worker runs, from the control plane's settings: blank keeps the pinned digest, as
/// `ScannerImages.PINNED.withOverrides` does.
///
/// **Refused, rather than ignored, what this runner cannot honour yet**: `host-ssh: false` and a `bundled-rules`
/// override change what a scan reads and how it clones, and the shared runner always clones with the host's SSH and
/// always places the bundled rules. Starting anyway would run a scan the operator configured against.
pub fn images(scanning: &Scanning) -> Result<Images, String> {
    if !scanning.host_ssh {
        return Err(
            "vectispire.scanning.host-ssh=false is not honoured by the Rust control plane's built-in worker yet: \
                    it always clones with the host's SSH. Leave it at true, or switch the worker off."
                .to_owned(),
        );
    }
    if scanning.bundled_rules.is_some() {
        return Err(
            "vectispire.scanning.bundled-rules is not honoured by the Rust control plane's built-in worker yet: \
                    it always places the bundled rules. Remove the override, or switch the worker off."
                .to_owned(),
        );
    }
    let ScannerImages { syft, grype, gitleaks, checkov, semgrep } = &scanning.images;
    let pick = |configured: &Option<String>, pinned: String| {
        configured.as_deref().map(str::trim).filter(|image| !image.is_empty()).map_or(pinned, str::to_owned)
    };
    // Nothing looked up: the pinned set.
    let pinned = Images::from_lookup(|_| None);
    Ok(Images {
        syft: pick(syft, pinned.syft),
        grype: pick(grype, pinned.grype),
        gitleaks: pick(gitleaks, pinned.gitleaks),
        checkov: pick(checkov, pinned.checkov),
        semgrep: pick(semgrep, pinned.semgrep),
    })
}
