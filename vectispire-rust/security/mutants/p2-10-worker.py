#!/usr/bin/env python3
"""Mutation check of Phase 2 task 2.10: the built-in worker — its loop (one round at a time, off when switched off),
the runner's image scan (the target dispatched to its one step, the SBOM and the match kept, the executor announced
as exporting images), the worker's options (`host-ssh`, `bundled-rules`) as the settings say and as the runner applies
them, the runtime's trust handed to the clone, the images read from the settings, and the start refused when no
runner can be built. See README.md.

Most mutants are killed by `cp-app/tests/worker_runs_a_scan.rs`, which starts the binary on a MySQL with the test forge
and the real scanner images (Docker, `ssh-agent` and `ssh-add` required; a few minutes per mutant, ten when the scan
is left pending and the test waits it out). The loop's by `cp-scanning`'s `worker_offload`, the settings' by
`cp-app`'s `worker_composition`, the operator's rules directory by the runner's own unit test.
"""
import sys

import _runner

RUNNER = "crates/runner/src/lib.rs"
APP = "crates/cp-app/src/worker.rs"
MAIN = "crates/cp-app/src/main.rs"
LOOP = "crates/cp-scanning/src/internal/worker/mod.rs"

BINARY = ["-p", "vectispire-cp-app", "--test", "worker_runs_a_scan"]
IMAGE = BINARY + ["the_started_binary_s_worker_exports"]
NO_HOST_SSH = BINARY + ["with_host_ssh_off"]
TRUST = BINARY + ["a_forge_behind_a_private_authority"]
REFUSED = BINARY + ["a_worker_whose_runner_cannot_be_built"]
COMPOSED = ["-p", "vectispire-cp-app", "--test", "worker_composition"]
OFFLOAD = ["-p", "vectispire-cp-scanning", "--test", "worker_offload"]
UNIT = ["-p", "vectispire-runner", "--lib"]

MUTANTS = [
    # ── the loop ──
    ("a switched-off worker ticks", LOOP, "        if !self.properties.enabled {", "        if false {", OFFLOAD),
    ("rounds stack up", LOOP,
     "        if self.busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {",
     "        if { self.busy.store(true, Ordering::Release); false } {", OFFLOAD),
    ("a finished round stays busy", LOOP, "        self.0.store(false, Ordering::Release);", "", OFFLOAD),

    # ── an image ──
    ("an image is handed back", RUNNER,
     "            Target::Image(image) => return self.run_image(image, started).await,",
     "            Target::Image(_) => return Err(transient(\"not run\".to_owned())),", IMAGE),
    # The flag feeds the executor's announcement only (`dispatcher::probe`, as Java's `ScanDispatcher.probe`), not the
    # claim: the started image scan completes either way, so it is held by the runner's own test.
    ("the executor announces no image", RUNNER,
     "    pub fn exports_images(&self) -> bool {\n        self.containers.exports_images()",
     "    pub fn exports_images(&self) -> bool {\n        false",
     UNIT),
    ("an image's SBOM is dropped", RUNNER,
     "        if let Some(sbom) = sbom {\n            artifacts.sbom = raw(&sbom);\n        }\n        match step {",
     "        let _ = sbom;\n        match step {", IMAGE),
    ("an image's match is dropped", RUNNER,
     "        match step {\n            Ok(done) => artifacts.dependencies = findings(&done.dependencies),",
     "        match step {\n            Ok(_) => {}", IMAGE),

    # ── host-ssh and the bundled rules ──
    ("the runner always clones with the host's SSH", RUNNER,
     "            without_key: self.without_key,", "            without_key: WithoutKey::HostSsh,", NO_HOST_SSH),
    ("host-ssh is not read", APP,
     "if scanning.host_ssh { WithoutKey::HostSsh } else { WithoutKey::None }", "WithoutKey::HostSsh", COMPOSED),
    ("a blank rules directory is an override", APP,
     "scanning.bundled_rules.as_deref().filter(|path| !path.trim().is_empty()).map(PathBuf::from)",
     "scanning.bundled_rules.as_deref().map(PathBuf::from)", COMPOSED),
    ("the rules directory is not read", APP,
     "scanning.bundled_rules.as_deref().filter(|path| !path.trim().is_empty()).map(PathBuf::from)", "None", COMPOSED),
    ("the operator's directory is not placed", RUNNER,
     "            Some(directory) => (None, RulePlacement::new(directory)),",
     "            Some(_) => {\n"
     "                let bundled = rules::materialise_in(&places.work).map_err(|error| error.to_string())?;\n"
     "                let placement = RulePlacement::new(bundled.tree());\n"
     "                (Some(bundled), placement)\n"
     "            }", UNIT),
    ("an empty directory is placed", RUNNER,
     "match options.bundled_rules.filter(|path| !path.as_os_str().is_empty()) {", "match options.bundled_rules {",
     UNIT),

    # ── the trust, the images, the start ──
    ("the clone trusts the compiled-in authorities only", MAIN,
     "            trust.clone(),\n            vectispire_cp_app::worker::options(&settings.scanning),",
     "            vectispire_tls::TlsTrust::BuiltIn,\n            vectispire_cp_app::worker::options(&settings.scanning),",
     TRUST),
    ("a blank image is an override", APP,
     "configured.as_deref().map(str::trim).filter(|image| !image.is_empty()).map_or(pinned, str::to_owned)",
     "configured.as_deref().map(str::trim).map_or(pinned, str::to_owned)", COMPOSED),
    ("the worker runs without a runner", APP,
     "        let runs = worker.enabled && runs_scans_here;", "        let runs = worker.enabled;", COMPOSED),
    ("a runner that cannot be built is a warning", MAIN,
     "could not be built: {error}\");\n                return ExitCode::FAILURE;",
     "could not be built: {error}\");\n                None", REFUSED),
]

# Not listed:
# - the platform handed to the pull (`container/src/runner.rs`): on Docker's containerd image store the save exports
#   the host's variant whatever was pulled, so no archive this test can read tells a pull for `linux/amd64` from one
#   for the host's own — measured 2026-11-15, Docker 29.1 on arm64. A defect of Java's as much as of this port.
# - the archive's removal after the inventory: `scanners::dependencies::sbom_of_image`'s, the dependencies stream's;
#   the workspace's own removal would get it anyway, so no test of the worker can tell.

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=1500, env={"VECTISPIRE_TEST_ENGINES": "mysql"}))
