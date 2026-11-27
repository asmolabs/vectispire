//! **An image target, copied into the workspace by a pinned step in a pod of its own** (decision 0045 §8) — `ImageCopy`:
//! what the Docker executor's pull and save do through the daemon, on a cluster that has none.
//!
//! **crane, not the cataloguer.** The step that reaches the registry is the only one with network and with the
//! registry's login; syft and grype read the archive it wrote offline, as on Docker. Letting the cataloguer pull would
//! hand network and credentials to the parser of hostile metadata.
//!
//! **A Docker archive, not the OCI layout 0045 §8 first named.** `crane pull`'s default format is the archive
//! `docker save` writes (`manifest.json`, the configuration, the layers): the cataloguer reads it through the same
//! `docker-archive:` source, and the platform check of [`vectispire_container::image_archive`] reads it unchanged.
//! Syft's whole report on the two archives of one image is the same, file names aside (measured on
//! `python:3.12-slim-bookworm`, linux/amd64, 113 packages): no fingerprint can move.
//!
//! **The platform is asked for and then checked.** Normalized as containerd normalizes before crane searches an index
//! for it; and a reference naming one image rather than an index is fetched whatever the platform, crane exiting 0 —
//! so the archive goes through the same check as the daemon's save, with this step's sentence.
//!
//! Held to `reference/kubernetes/image-copy.json`, which `KubernetesReferenceSetTest.theImageCopy` writes.

use std::path::Path;
use vectispire_container::{ContainerRun, Extras, Mount, RegistryLogin};

/// crane 0.22.1, the multi-architecture index: a static binary, no shell.
pub const IMAGE: &str =
    "gcr.io/go-containerregistry/crane:v0.22.1@sha256:1f968817b95790bed063f71175aa6b8ff879fa17064020415f3e18bb6e6a36e1";
/// What the image runs, declared as every scanner's is: the wrapper that captures its streams has to name it.
pub const ENTRYPOINT: &[&str] = &["/ko-app/crane"];
/// The step's name: its pod's, and its failures'.
pub const LABEL: &str = "image copy";
/// Where the copy's writable directory is in its pod.
pub const TARGET: &str = "/image";
/// The archive crane writes there, brought back by the executor's copy of a writable mount.
pub const ARCHIVE: &str = "image.tar";
/// What the archive may hold: the work volume's size and the copy back's ceiling. Generous — an image's compressed
/// layers rarely pass a few gigabytes — since past it the step fails outright.
pub const BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// The copy's run and its login: crane pulling `reference` for `platform` (normalized, `None` when the task named
/// none) into `into`, online, handed the registry's login under `login` when the agent holds one.
///
/// **`--` before the reference**: a reference is the operator's text, and one starting with a dash would otherwise be
/// read as one of crane's options (`--insecure`).
pub fn request(
    image: &str,
    reference: &str,
    platform: Option<&str>,
    into: &Path,
    login: &Path,
) -> (ContainerRun, Extras) {
    let mut command = vec!["pull".to_owned()];
    if let Some(asked) = platform {
        command.extend(["--platform".to_owned(), asked.to_owned()]);
    }
    command.extend(["--".to_owned(), reference.to_owned(), format!("{TARGET}/{ARCHIVE}")]);
    let mut run = ContainerRun::new(
        image,
        command,
        vec![Mount::writable_sized(into.display().to_string(), TARGET, BYTES)],
        LABEL,
    )
    .with_entrypoint(ENTRYPOINT);
    run.network = true;
    let extras = Extras {
        output: None,
        login: Some(RegistryLogin { reference: reference.to_owned(), directory: login.to_owned() }),
    };
    (run, extras)
}

/// Why the copy produced nothing to scan, in its own words — `None` when it exited 0 and wrote its archive.
/// `stderr` is what crane printed, already redacted of the login by the executor.
pub fn failure(reference: &str, platform: &str, exit_code: i64, stderr: &str, written: bool) -> Option<String> {
    if exit_code != 0 {
        let asked =
            if vectispire_domain::java::is_blank(platform) { String::new() } else { format!(" for {platform}") };
        let said = excerpt(vectispire_domain::java::strip(stderr));
        let said = if said.is_empty() { String::new() } else { format!(", saying: {said}") };
        return Some(format!(
            "The image copy could not fetch {reference}{asked}: crane exited {exit_code}{said}. It is not scanned."
        ));
    }
    if !written {
        return Some(format!("The image copy exited 0 and wrote no archive of {reference}. It is not scanned."));
    }
    None
}

/// The first 500 characters — code points, as Java's side counts them.
pub fn excerpt(text: &str) -> String {
    if text.chars().count() <= 500 {
        text.to_owned()
    } else {
        format!("{}…", text.chars().take(500).collect::<String>())
    }
}
