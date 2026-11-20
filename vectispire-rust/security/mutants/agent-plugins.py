#!/usr/bin/env python3
"""Mutation check of the agent's plugins stream: crates/scanners/src/{plugins,sarif}.rs, the domain's manifest, signer
and image rules, crates/container's bounded output, archive, df and pull credentials, the create requests of the holder,
the plugin and cosign, and the runner's record of the steps — each guard against reference/plugins/ or a unit test.
See README.md.
"""
import sys

import _runner

S = ["-p", "vectispire-scanners", "--test", "plugins_reference_set"]
SL = ["-p", "vectispire-scanners", "--lib"]
CR = ["-p", "vectispire-scanners", "--test", "plugin_creates"]
C = ["-p", "vectispire-container", "--test", "plugin_runs_reference_set"]
CL = ["-p", "vectispire-container", "--lib"]
RL = ["-p", "vectispire-runner", "--lib"]
P = "crates/scanners/src/plugins.rs"
Q = "crates/scanners/src/sarif.rs"
B = "crates/container/src/bounded_output.rs"
K = "crates/container/src/pull_credentials.rs"
W = "crates/container/src/run_with.rs"
M = "crates/domain/src/plugin_manifest.rs"
G = "crates/domain/src/plugin_signature.rs"
I = "crates/domain/src/plugin_image.rs"

# Equivalent, and not listed: the holder's `df` column held under 19 digits — a value of 19 digits overflows `long` and
# is dropped by the parse as by the length test; Docker Hub's key matched before the exact lookup — the exact lookup
# finds the same key; the prescan's string tracking against a quote inside a key — keys are strings either way; the
# page threshold moved to 4095 bytes — `df -P -k` prints whole KiB, so no measurement lands between 4095 and 4096; and
# `content`'s `size < 0` — `usize::try_from` refuses a negative size with the same sentence right after it.
MUTANTS = [
    # Admission: who may run, before anything is pulled.
    ("not required read as required", P, "if !self.settings.signature_required {", "if self.settings.signature_required {", S),
    ("waiver ignored", P, "        if runs_unsigned {\n            return Ok(Signature::Waived);", "        if !runs_unsigned {\n            return Ok(Signature::Waived);", S),
    ("root owner runs", P, "if owner.starts_with(\"0:\") {", "if owner.starts_with(\"0:0:\") {", S),
    ("signature not checked before the run", P, "verify(&self.executor, &image, declared, &keys, &owner, &label, &cosign).await?;", "let _ = verify(&self.executor, &image, declared, &keys, &owner, &label, &cosign).await;", S),
    ("network granted to every plugin", P, "        if manifest.network {\n", "        if !manifest.network {\n", S),
    ("holder not relocated", P, "let holder = self.settings.relocate(OUTPUT_HOLDER).map_err(refused)?;", "let holder = OUTPUT_HOLDER.to_owned();", S),
    # cosign's verdict.
    ("cosign exit 1 believed", P, "    if result.exit_code == 0 {\n        return Ok(());", "    if result.exit_code <= 1 {\n        return Ok(());", S),
    ("registry refusal matched inside words", P, r'r"\b(?:UNAUTHORIZED|DENIED)\b|\b401 Unauthorized\b|\b403 Forbidden\b"', r'r"(?:UNAUTHORIZED|DENIED)|401 Unauthorized|403 Forbidden"', S),
    ("credentials held and none told apart wrongly", P, "let opening = if access.credentials_held {", "let opening = if !access.credentials_held {", S),
    ("cosign quoted past 2000", P, "let quoted = first_units(said, 2000);", "let quoted = first_units(said, 3000);", S),
    ("transparency log consulted for a key", P, "            command.push(\"--insecure-ignore-tlog=true\".to_owned());\n", "", [S, CR]),
    ("key mounted writable", P, "mounts.push(Mount::read_only(file.display().to_string(), KEY_MOUNT));", "mounts.push(Mount::writable(file.display().to_string(), KEY_MOUNT));", S),
    # The run's outcome, in Java's order.
    ("a full directory believed", P, "    if output.full() {\n", "    if false && output.full() {\n", S),
    ("sigxfsz read as a declared code", P, "if exit_code == FILE_TOO_LARGE_EXIT && !declared(exit_code) {", "if exit_code == FILE_TOO_LARGE_EXIT {", S),
    ("undeclared exit believed", P, "    if !declared(exit_code) {\n        return Err(ScannerError::exited", "    if false {\n        return Err(ScannerError::exited", S),
    ("a failed run's findings kept", P, "        if !run.successful {\n", "        if false {\n", S),
    ("a run without results read as empty", P, "let Some(results) = &run.results else { return Ok(None) };", "let Some(results) = &run.results else { continue };", S),
    # The steps.
    ("another digest believed", P, " || manifest.digest() != reference.digest {", " {", S),
    ("manifest not validated", P, "    manifest.validated().map_err(|refused| format!(\"its definition could not be obtained: {}\", refused.0))?;\n", "", S),
    ("absent root examined", P, ".filter(|root| std::fs::symlink_metadata(root).is_ok_and(|metadata| metadata.is_dir()));", ".filter(|_| true);", S),
    ("every plugin applicable", P, "!complete || declared.iter().any(|language| found.contains(language))", "true", S),
    ("a text boolean refused", P, "\"true\" | \"True\" | \"TRUE\" => Some(true),", "\"True\" | \"TRUE\" => Some(true),", S),
    # SARIF: the document.
    ("duplicate keys resolved", Q, "            if members.contains_key(&key) {\n", "            if false {\n", S),
    ("nesting unbounded", Q, "                if depth > MAX_DEPTH {\n", "                if depth > MAX_DEPTH + 10 {\n", S),
    ("a long number read", Q, "            if digits > MAX_NUMBER {\n", "            if digits > MAX_NUMBER + 1 {\n", S),
    ("content after the end believed", Q, "Next::Token => Err(invalid(\"The SARIF document carries content after its end.\")),", "Next::Token => Ok(Some(value)),", S),
    ("external properties followed", Q, "    if present(root.get(\"inlineExternalProperties\")) {\n", "    if false {\n", S),
    ("results unbudgeted", Q, ".checked_sub(results.len())", ".checked_sub(0)", S),
    ("a byte-order mark refused", Q, r'.strip_prefix(b"\xef\xbb\xbf")', r'.strip_prefix(b"\xef\xbb\xbf\xff")', S),
    # SARIF: the findings.
    ("an accepted suppression imported", Q, "\"accepted\") == \"accepted\");", "\"accepted\") == \"underReview\");", S),
    ("not applicable imported", Q, "    if kind == \"pass\" || kind == \"notApplicable\" {\n", "    if kind == \"pass\" {\n", S),
    ("critical boundary moved", Q, "        return if value >= 9.0 {\n", "        return if value > 9.0 {\n", S),
    # SARIF: the paths, fingerprint material.
    ("dot-dot kept", Q, "        if segment == \"..\" {\n", "        if segment == \"...\" {\n", S),
    ("any scheme followed", Q, "        if java::to_lower_root(scheme) != \"file\" {\n", "        if false {\n", S),
    ("a sibling of the root taken for it", Q, "if let Some(rest) = absolute.strip_prefix(root).and_then(|rest| rest.strip_prefix('/')) {", "if let Some(rest) = absolute.strip_prefix(root) {", S),
    ("another host's file followed", Q, "if !host.is_empty() && !host.eq_ignore_ascii_case(\"localhost\") {", "if !host.is_empty() && false {", S),
    ("a control character kept", Q, "    if has_control(&decoded) {\n", "    if false {\n", S),
    # The bounded output.
    ("no inode left is room", B, "self.available_bytes < 4096 || self.available_inodes <= 0", "self.available_bytes < 4096 || self.available_inodes < 0", C),
    ("a link read as the report", B, "let regular = kind == b'0' || kind == 0;", "let regular = true;", C),
    ("another file read as the report", B, "if !regular || name != file {", "if !regular {", C),
    ("too large past the ceiling only", B, "if size > i64::try_from(ceiling).unwrap_or(i64::MAX) {", "if size > i64::try_from(ceiling).unwrap_or(i64::MAX).saturating_add(1) {", C),
    ("pax size ignored", B, "        if let Some(pending) = pending_size {\n            size = pending;\n        }\n", "", C),
    ("extended header unbounded", B, "const MAX_META: u64 = 64 * 1024;", "const MAX_META: u64 = 64 * 1024 + 1;", C),
    # Pull credentials: docker-java's rule.
    ("a user without a password usable", K, "(self.username.is_some() && self.password.is_some())\n", "(self.username.is_some())\n", C),
    ("a key with a scheme not matched", K, ".find(|(key, _)| to_hostname(key) == normalized)", ".find(|(key, _)| key.as_str() == normalized)", C),
    ("the password not redacted", K, "        redacted = replace(&redacted, self.password.as_deref());\n", "", C),
    ("an auth without a colon read", K, ".split_once(':').ok_or_else(|| UNPARSABLE.to_owned())?;", ".split_once(':').unwrap_or((decoded.as_str(), \"\"));", C),
    ("the login file readable by others", K, "std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);", "std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o644);", CL),
    # The create requests.
    ("no fsize hard limit", W, "soft: Some(size), hard: Some(size)", "soft: Some(size), hard: None", CR),
    ("the holder's directory open to all", W, "mode=0700,noexec,nosuid,nodev", "mode=0777,noexec,nosuid,nodev", CR),
    ("the login mounted writable", W, "run.mounts.push(Mount::read_only(directory.display().to_string(), REGISTRY_LOGIN_MOUNT));", "run.mounts.push(Mount::writable(directory.display().to_string(), REGISTRY_LOGIN_MOUNT));", CR),
    # The signer.
    ("rsa of 1024 bits accepted", G, "            if bits < MIN_RSA_BITS {\n", "            if bits < 1024 {\n", S),
    ("any curve accepted", G, "if !curve.is_some_and(|curve| CURVES.contains(&curve.as_str())) {", "if curve.is_none() {", S),
    ("ed448 accepted", G, "        ED25519 => {}\n", "        ED25519 | \"1.3.101.113\" => {}\n", S),
    ("two blocks accepted", G, "Some((kind, der)) if kind == \"PUBLIC KEY\" && !more => der,", "Some((kind, der)) if kind == \"PUBLIC KEY\" => der,", S),
    ("a space in an identity", G, "value.chars().any(|c| java::is_whitespace(c) || java::is_iso_control(c))", "value.chars().any(java::is_iso_control)", S),
    ("an http issuer", G, "if !issuer.starts_with(\"https://\") {", "if !issuer.starts_with(\"http\") {", S),
    # The manifest.
    ("nine exit codes", M, "if self.exit_codes.len() > MAX_EXIT_CODES {", "if self.exit_codes.len() > MAX_EXIT_CODES + 1 {", S),
    ("the signer outside the digest", M, "            fields.extend(signature.digest_fields().into_iter().map(Some));\n", "", S),
    ("another major's digest unchanged", M, "if version(&self.schema_version).is_none_or(|(major, _)| major != SCHEMA_MAJOR) {", "if false {", S),
    ("a tab refused", M, "c != '\\n' && c != '\\t' && crate::java::is_iso_control(c)", "c != '\\n' && crate::java::is_iso_control(c)", S),
    ("a short justification", M, "(MIN_JUSTIFICATION..=MAX_JUSTIFICATION).contains(&length)", "(0..=MAX_JUSTIFICATION).contains(&length)", S),
    ("a timeout past the scanners'", M, "!(MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&seconds)", "!(MIN_TIMEOUT_SECONDS..=901).contains(&seconds)", S),
    # The image.
    ("a tag beside the digest", I, "    if last_segment.contains(':') {\n", "    if false {\n", S),
    ("localhost read as Hub", I, "if first.contains('.') || first.contains(':') || first == \"localhost\" {", "if first.contains('.') || first.contains(':') {", S),
    ("a credential in the mirror", I, " || trimmed.contains('@')", "", S),
    # The runner's record.
    ("a failure not under the plugin's name", "crates/runner/src/lib.rs", "artifacts.failed(format!(\"plugin {plugin_id}\"), reason.clone());", "artifacts.failed(plugin_id.clone(), reason.clone());", RL),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, description=__doc__))
