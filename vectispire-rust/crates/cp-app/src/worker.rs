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
//!
//! `host-ssh: false` and a `bundled-rules` override were then refused at start, the shared runner honouring neither;
//! both are honoured since 2.10 was finished (2026-11-15), as `ScanningConfiguration.scanRunner` honours them.

use std::path::PathBuf;
use vectispire_cp_runtime::settings::{ScannerImages, Scanning, Worker};

use vectispire_runner::{Images, Options, WithoutKey};

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
#[must_use]
pub fn images(scanning: &Scanning) -> Images {
    let ScannerImages { syft, grype, gitleaks, checkov, semgrep } = &scanning.images;
    let pick = |configured: &Option<String>, pinned: String| {
        configured.as_deref().map(str::trim).filter(|image| !image.is_empty()).map_or(pinned, str::to_owned)
    };
    // Nothing looked up: the pinned set.
    let pinned = Images::from_lookup(|_| None);
    Images {
        syft: pick(syft, pinned.syft),
        grype: pick(grype, pinned.grype),
        gitleaks: pick(gitleaks, pinned.gitleaks),
        checkov: pick(checkov, pinned.checkov),
        semgrep: pick(semgrep, pinned.semgrep),
    }
}

/// What the worker's runner does that the agent's does not decide the same way — `ScanningConfiguration.scanRunner`.
///
/// - **`host-ssh`**: a repository with no deployment key is cloned with the host's SSH only when it says so; off, a
///   private one is refused. Inside the control plane the host's identity would clone any target anybody adds.
/// - **`bundled-rules`**: a directory named here is read in place of the rules the binary carries; blank unpacks those.
#[must_use]
pub fn options(scanning: &Scanning) -> Options {
    Options {
        without_key: if scanning.host_ssh { WithoutKey::HostSsh } else { WithoutKey::None },
        bundled_rules: scanning.bundled_rules.as_deref().filter(|path| !path.trim().is_empty()).map(PathBuf::from),
    }
}
