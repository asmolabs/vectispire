#!/usr/bin/env python3
"""Mutation check of image targets on the Kubernetes executor (decision 0045 §8, branch rust/agent-k8s-image-targets,
2026-11-27): crane copies the image in a pod of its own, online, handed the registry's login, and the archive it wrote is
checked against the platform asked with the copy's own sentence. Each mutant must turn a test red. See README.md.

The request, the sentences and the platform rules are killed by the reference set Java wrote
(`reference/kubernetes/image-copy.json`, no cluster). What only a pod shows — the archive brought back, a single image
of another platform refused and removed, the copy's directories gone after — is killed by `--test on_k3s`
(`the_image_copy_on_k3s`: k3s in Docker, and Alpine 3.20.3 pulled from Docker Hub, about a minute each).

What a missed guard costs: the inventory of an architecture nobody deploys recorded as the image's; a reference read as
one of crane's options; the cataloguer handed an archive nobody checked; an image target refused outright on a cluster.
"""
import sys

import _runner

C = "crates/kubernetes/src/image_copy.rs"
E = "crates/kubernetes/src/executor.rs"
A = "crates/container/src/image_archive.rs"
REF = ["-p", "vectispire-kubernetes", "--test", "reference_set", "--", "the_image_copy"]
K3S = ["-p", "vectispire-kubernetes", "--test", "on_k3s", "--", "the_image_copy_on_k3s"]
CLAIMED = ["-p", "vectispire-kubernetes", "--test", "on_k3s", "--", "the_executor_on_k3s"]

MUTANTS = [
    # The copy's run.
    ("no -- before the reference", C, 'command.extend(["--".to_owned(), reference.to_owned(),',
     "command.extend([reference.to_owned(),", REF),
    ("the platform not asked", C, '        command.extend(["--platform".to_owned(), asked.to_owned()]);\n', "", REF),
    ("offline", C, "    run.network = true;\n", "", REF),
    ("a writable mount of the output ceiling", C, "Mount::writable_sized(into.display().to_string(), TARGET, BYTES)",
     "Mount::writable(into.display().to_string(), TARGET)", REF),
    ("crane's entrypoint undeclared", C, "    .with_entrypoint(ENTRYPOINT);", "    ;", REF),
    ("the mirror ignored", E, "self.copy_image = if image.is_empty() { image_copy::IMAGE.to_owned() } else { image.to_owned() };",
     "self.copy_image = image_copy::IMAGE.to_owned();", REF),
    # What crane's end becomes.
    ("crane's exit ignored", C, "    if exit_code != 0 {", "    if false {", REF),
    ("no archive believed", C, "    if !written {", "    if false {", REF),
    ("a blank platform named", C, "if vectispire_domain::java::is_blank(platform) {", "if platform.is_empty() {", REF),
    ("crane's words trimmed as Rust trims", C, "excerpt(vectispire_domain::java::strip(stderr))", "excerpt(stderr.trim())", REF),
    ("the excerpt by bytes", C, "if text.chars().count() <= 500 {", "if text.len() <= 500 {", REF),
    # The platform: asked normalized, refused in the copy's words.
    ("the platform not normalized", A, "Ok(requested(platform)?.map(|asked| asked.format()))",
     "Ok(requested(platform)?.map(|_| platform.to_owned()))", REF),
    ("the daemon's sentence for the copy", A, '"The image copy fetched {reference} as {found} where',
     '"The Docker daemon exported {reference} as {found} where', REF),
    # The export, on a cluster.
    ("image targets not claimed", E, "    fn exports_images(&self) -> bool {\n        true", "    fn exports_images(&self) -> bool {\n        false",
     CLAIMED),
    ("the copied archive not checked", E,
     "        let Some(asked) = vectispire_container::image_archive::requested(platform).map_err(ExportError::Platform)?\n",
     "        let Some(asked) = None::<vectispire_container::image_archive::Platform>\n", K3S),
    ("a refused archive left behind", E,
     "                let _ = std::fs::remove_file(destination);\n                Err(ExportError::Copy(refusal))",
     "                Err(ExportError::Copy(refusal))", K3S),
    ("the copy's directory left", E, "        drop(copy);\n", "        let _ = copy.keep();\n", K3S),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900, description=__doc__))
