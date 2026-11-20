#!/usr/bin/env python3
"""Mutation check of the Kubernetes executor's plugin capabilities (decision 0045): a plugin's bounded output and its
registry login, ported from Java's `KubernetesExecutor` on 2026-11-20. Each mutant must turn a test red. See README.md.

Most are killed by the reference set Java wrote (`--test reference_set`, no cluster) or by the JDK's own answers for
an `auth` (`vectispire-container`'s unit test). What only a pod shows — the output read back, the login copied in,
erased after, and redacted from what the tool and its failures say — is killed by `--test on_k3s` (k3s in Docker,
about a minute each).
"""
import sys

import _runner

K = "crates/kubernetes/src/"
P = "crates/container/src/pull_credentials.rs"
REF = ["-p", "vectispire-kubernetes", "--test", "reference_set"]
CREDENTIALS = [["-p", "vectispire-container", "--lib", "pull_credentials"],
               ["-p", "vectispire-container", "--test", "plugin_runs_reference_set"], REF]
K3S = ["-p", "vectispire-kubernetes", "--test", "on_k3s", "--", "the_plugins_needs_on_k3s"]

MUTANTS = [
    # The pod a bounded output becomes.
    ("no output volume", K + "pods.rs", "        volumes.push(memory_volume(OUTPUT, &output.bytes.to_string()));\n", "", REF),
    ("the output volume larger than declared", K + "pods.rs", "memory_volume(OUTPUT, &output.bytes.to_string())",
     "memory_volume(OUTPUT, &output.bytes.saturating_add(1).to_string())", REF),
    ("the plugin cannot write its output", K + "pods.rs", "mount(&mut scanner, OUTPUT, &output.target, false, None);",
     "mount(&mut scanner, OUTPUT, &output.target, true, None);", REF),
    ("the holder may write the output", K + "pods.rs", "mount(&mut holder, OUTPUT, &output.target, true, None);",
     "mount(&mut holder, OUTPUT, &output.target, false, None);", REF),
    # The holder's probe, and what its answer settles.
    ("a link probed as a file", K + "executor.rs", 'if [ -L \\"$f\\" ]; then echo kind=other; elif [ ! -e', "if [ ! -e", REF),
    ("a missing file read", K + "executor.rs", '    if answer.contains("kind=missing") {', "    if false {", REF),
    ("a file of the ceiling's size refused", K + "executor.rs", "Ok(size) if size > ceiling =>", "Ok(size) if size >= ceiling =>", REF),
    ("the size read unstripped", K + "executor.rs", "read_long(vectispire_domain::java::strip(size))", "read_long(size)", REF),
    ("an unreadable size read as a file to read", K + "executor.rs",
     '.ok_or_else(|| format!("its holder gave a size that is not a number: \\"{}\\".", excerpt(size)))?;',
     ".unwrap_or(0);", REF),
    ("the directory's ceiling alone", K + "executor.rs", "let ceiling = bounded.bytes.min(self.settings.output_bytes());",
     "let ceiling = bounded.bytes;", K3S),
    ("the output never collected", K + "executor.rs", "Some(bounded) => Some(self.collect(pod, bounded, label).await?),",
     "Some(_) => None,", K3S),
    ("the file never read", K + "executor.rs", "                    OutputFile::Read(content.stdout)\n",
     "                    OutputFile::Read(Vec::new())\n", K3S),
    # The registry login.
    ("a bounded output without its user run", K + "executor.rs", "if extras.output.is_some() && request.user.is_none() {",
     "if false {", REF),
    ("an unreadable secret read as none", K + "executor.rs",
     ".map_err(|unreadable| extended_failure(label, unreadable.to_string()))?,", ".unwrap_or(None),", REF),
    ("credentials never held", K + "executor.rs", "reference), Ok(Some(_)));", "reference), Ok(None));", REF),
    ("the login not mounted", K + "executor.rs",
     "        with_login.mounts.push(Mount::read_only(written.display().to_string(), REGISTRY_LOGIN_MOUNT));\n", "", K3S),
    ("the login left behind", K + "executor.rs", "        drop(erasure);\n", "        std::mem::forget(erasure);\n", K3S),
    ("the tool's words not redacted", K + "executor.rs", "stdout: credentials.redact(&result.stdout),", "stdout: result.stdout,", K3S),
    ("a failure not redacted", K + "executor.rs",
     "Err(if redacted == said { ExtendedError::Runner(failure) } else { extended_failure(label, redacted) })",
     "Err(ExtendedError::Runner(failure))", K3S),
    ("the secret set at start ignored", K + "choice.rs",
     "        settings = settings.with_registry_credentials(Some(credentials.to_path_buf()));\n", "",
     ["-p", "vectispire-kubernetes", "--test", "on_k3s", "--", "the_choice_at_start"]),
    # The secret read as docker-java reads it.
    ("an auth outside the alphabet read", P,
     "let Some(sextet) = ALPHABET.iter().position(|c| *c == byte).and_then(|at| u8::try_from(at).ok()) else {",
     "let Some(sextet) = Some(ALPHABET.iter().position(|c| *c == byte).and_then(|at| u8::try_from(at).ok()).unwrap_or(0)) else {",
     CREDENTIALS),
    ("a unit's last sextet dropped", P, "                c.wrapping_shl(6) | d,\n", "                c.wrapping_shl(6),\n", CREDENTIALS),
    ("padding required", P, '        [] => return Ok(Vec::new()),\n', '        [] => return Ok(Vec::new()),\n        bytes if bytes.len() % 4 != 0 => return Err("padding".to_owned()),\n', CREDENTIALS),
    ("one `=` where two are due", P, "                2 => !matches!(bytes.next(), Some((_, b'='))),", "                2 => false,", CREDENTIALS),
    ("bytes after the padding read", P, "    if let Some((at, _)) = bytes.next() {", "    if let Some((at, _)) = None::<(usize, u8)> {", CREDENTIALS),
    ("this port's words for a broken secret", P, 'const UNPARSABLE: &str = "Failed to parse docker configuration file";',
     'const UNPARSABLE: &str = "Failed to parse docker config.json";', CREDENTIALS),
    ("a colon-less auth read", P, ".ok_or_else(|| UNPARSABLE.to_owned())?;", ".unwrap_or((decoded.as_str(), \"\"));", CREDENTIALS),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=1800))
