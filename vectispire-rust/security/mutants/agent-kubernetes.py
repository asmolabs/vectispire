#!/usr/bin/env python3
"""Mutation check of the agent's Kubernetes executor (decision 0045): crates/kubernetes and the agent's choice of it.
Each mutant must turn a test red. See README.md.

Most are killed by the reference set Java wrote (`--test reference_set`, no cluster) or the crate's unit tests. The
guards only a cluster can see — the gate before the scanner, Pod Security and isolation at start, the handshake's
answer — are killed by `--test on_k3s`, which starts k3s in Docker (a few minutes each).
"""
import sys

import _runner

K = "crates/kubernetes/src/"
REF = ["-p", "vectispire-kubernetes", "--test", "reference_set"]
LIB = ["-p", "vectispire-kubernetes", "--lib"]
K3S_CHOICE = ["-p", "vectispire-kubernetes", "--test", "on_k3s", "--", "the_choice_at_start"]
AGENT = ["-p", "vectispire-agent", "--bin", "vectispire-agent"]

CLOSED = '''        "runAsNonRoot": true,
        "runAsUser": uid,
        "runAsGroup": gid,
        "allowPrivilegeEscalation": false,'''
MUTANTS = [
    # The closed shape, as a pod expresses it (0045 §2).
    ("a container may run as root", K + "pods.rs", CLOSED, CLOSED.replace('"runAsNonRoot": true', '"runAsNonRoot": false'), REF),
    ("new privileges allowed", K + "pods.rs", '"allowPrivilegeEscalation": false,', '"allowPrivilegeEscalation": true,', REF),
    ("a writable root", K + "pods.rs", '"readOnlyRootFilesystem": true,', '"readOnlyRootFilesystem": false,', REF),
    ("capabilities kept", K + "pods.rs", '"capabilities": {"drop": ["ALL"]},', '"capabilities": {"drop": []},', REF),
    ("the pod gets a token", K + "pods.rs", 'spec.insert("automountServiceAccountToken".into(), json!(false));\n    spec.insert("enableServiceLinks"',
     'spec.insert("automountServiceAccountToken".into(), json!(true));\n    spec.insert("enableServiceLinks"', REF),
    ("no seccomp profile on the pod", K + "pods.rs", '"runAsGroup": gid,\n        "seccompProfile": {"type": "RuntimeDefault"},\n    });\n    let mut spec',
     '"runAsGroup": gid,\n        "seccompProfile": {"type": "Unconfined"},\n    });\n    let mut spec', REF),
    ("requests below limits", K + "pods.rs", '"requests": {"memory": memory_text, "cpu": cpu}', '"requests": {"memory": "0", "cpu": cpu}', REF),
    ("no backstop on the deadline", K + "pods.rs", ".saturating_add(timeout).saturating_add(BACKSTOP);", ".saturating_add(timeout);", REF),
    ("no margin on the work volume", K + "pods.rs", "            .saturating_add(WORK_MARGIN)\n", "", REF),
    ("the output ceiling not a floor", K + "pods.rs", "    total.max(output_bytes)\n", "    total\n", REF),
    ("a declared size ignored", K + "pods.rs", "if mount.writable_bytes > 0 { mount.writable_bytes } else { output_bytes }", "output_bytes", REF),
    ("online pods labelled offline", K + "pods.rs", "if request.network { ONLINE } else { OFFLINE }", "OFFLINE", REF),
    ("the cache's node never named", K + "pods.rs", "    if vectispire_domain::java::is_blank(node) {\n        return;", "    if true {\n        return;", REF),
    ("no DOCKER_CONFIG for a login", K + "pods.rs", 'environment.push(json!({"name": "DOCKER_CONFIG", "value": REGISTRY_LOGIN_MOUNT}));', "", REF),
    ("a long label", K + "pods.rs", ".chars().take(63).collect();", ".chars().take(64).collect();", REF),
    # A pod's status read as a failure (0045 §9).
    ("an unpullable image waited for", K + "pods.rs", "if CANNOT_START.contains(&reason.as_str()) {", "if false {", REF),
    ("a failed init container waited for", K + "pods.rs", '            if kind == "initContainerStatuses"\n                && terminated.is_some()',
     '            if false\n                && terminated.is_some()', REF),
    ("a failed pod waited for", K + "pods.rs", 'if json::text(json::path(status, "phase")) == "Failed" {', "if false {", REF),
    ("receiving before running", K + "pods.rs", '&& json::has(json::path(Some(container), "state"), "running")', '&& json::has(json::path(Some(container), "state"), "waiting")', REF),
    ("exit 137 read as the scanner's", K + "pods.rs", '|| json::int(json::path(Some(terminated), "exitCode")) == KILLED', "", REF),
    # The API server's address, before the token goes there.
    ("a name answering another host accepted", K + "address.rs", "if !named.iter().all(|address| service.contains(address)) {", "if !named.iter().any(|address| service.contains(address)) {", REF),
    ("port zero accepted", K + "address.rs", ".filter(|number| *number >= 1)", "", REF),
    ("an unbracketed IPv6 target accepted", K + "address.rs", "host.starts_with('[') && !bare.is_empty()", "!bare.is_empty()", REF),
    ("three-part addresses accepted", K + "address.rs", "parts.len() == 4", "parts.len() >= 3", REF),
    ("a target that is not an address accepted", K + "address.rs", "    if host.is_empty() || !host.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':') {\n        return Err(refused());",
     "    if host.is_empty() {\n        return Err(refused());", REF),
    # The exec stream.
    ("every fragment carries a channel", K + "channels.rs", "        if self.at_message_start\n", "        if true\n", REF),
    ("nothing kept past the ceiling", K + "channels.rs", "self.ceiling.saturating_add(1).saturating_sub(self.stdout_bytes)", "self.ceiling.saturating_sub(self.stdout_bytes)", REF),
    ("the ceiling itself refused", K + "channels.rs", "if self.stdout_bytes > self.ceiling {", "if self.stdout_bytes >= self.ceiling {", REF),
    ("stderr unbounded", K + "channels.rs", "Some(STDERR) => append(&mut self.stderr, body, STDERR_BYTES),", "Some(STDERR) => append(&mut self.stderr, body, usize::MAX),", REF),
    ("a later exit cause read", K + "channels.rs", "                        Err(_) => break,", "                        Err(_) => continue,", REF),
    # What comes back from the pod.
    ("directories counted as files", K + "archives.rs", "        if entry.directory() {", "        if false {", REF),
    ("a sparse file brought back", K + "archives.rs", "        if entry.sparse {", "        if false {", REF),
    ("no ceiling on the copy back", K + "archives.rs", "        if total > ceiling {", "        if false {", REF),
    ("a link brought back", K + "archives.rs", "        if !entry.regular() {", "        if false {", REF),
    ("a name climbing out written", K + "archives.rs", "if name.starts_with('/') || !target.starts_with(&root) || target == root {", "if name.starts_with('/') {", REF),
    ("written through a link", K + "archives.rs", "            if std::fs::symlink_metadata(&at).is_ok_and(|metadata| metadata.file_type().is_symlink()) {", "            if false {", REF),
    ("written over a link", K + "archives.rs", "        if std::fs::symlink_metadata(&target).is_ok_and(|metadata| metadata.file_type().is_symlink()) {", "        if false {", REF),
    ("a wrong checksum read", K + "archives.rs", "    if matches {", "    if true {", LIB),
    # The executor's pure parts.
    ("root asked", K + "executor.rs", "(Ok(uid), Ok(gid)) if uid > 0 => Ok((uid, gid)),", "(Ok(uid), Ok(gid)) => Ok((uid, gid)),", REF),
    ("any 403 is RBAC's", K + "executor.rs", 'refused.status == 403 && refused.message.contains("cannot create resource")', "refused.status == 403", REF),
    ("any refusal is Pod Security's", K + "executor.rs", 'refused.status == 403 && refused.message.contains("PodSecurity")', 'refused.message.contains("PodSecurity")', REF),
    ("placement sets anything", K + "executor.rs", "if let Some(field) = placement.keys().find(|field| !PLACEMENT.contains(&field.as_str())) {", "if let Some(field) = placement.keys().find(|_| false) {", REF),
    ("a long pod name", K + "executor.rs", "        .take(40)\n", "        .take(41)\n", REF),
    ("the probe pod gets a token", K + "executor.rs", '    spec.insert("automountServiceAccountToken".into(), json!(false));\n    spec.insert("containers"',
     '    spec.insert("containers"', REF),
    ("the Pod Security probe not privileged", K + "executor.rs", '"securityContext": {"privileged": true, "runAsUser": 0},', '"securityContext": {"runAsUser": 0},', REF),
    ("any directory is a generation", K + "executor.rs", "            && generation_name(&file_name(&absolute))", "", LIB),
    # The WebSocket framing.
    ("frames sent unmasked", K + "websocket.rs", ".map(|(byte, key)| byte ^ key)", ".map(|(byte, _)| *byte)", LIB),
    ("long control frames read", K + "websocket.rs", "if !fin || length > CONTROL_BYTES {", "if false {", LIB),
    ("any handshake answer accepted", K + "api.rs", "    if accept != websocket::accept_for(key) {", "    if false {", LIB),
    ("any subprotocol accepted", K + "api.rs", "    if protocol != EXEC_PROTOCOL {", "    if false {", LIB),
    ("a name starting with a dash", K + "api.rs", "        && bytes.first().is_some_and(alphanumeric)\n", "", LIB),
    # The choice at start.
    ("a pod with no CPU accepted", K + "choice.rs", "if cpu_millis <= 0 || memory_mib <= 0 {", "if memory_mib <= 0 {", REF),
    ("a placement that is not an object", K + "choice.rs", "Some(Value::Object(object)) => Ok(object),", "Some(Value::Object(object)) => Ok(object),\n        Some(_) => Ok(Map::new()),", REF),
    ("the kind read as written", K + "choice.rs", "vectispire_domain::java::to_lower_root(vectispire_domain::java::trim(configured))", "configured.to_owned()", REF),
    ("isolation not required by default", "crates/agent/src/config.rs", '"" | "true" | "on" | "yes" | "1" => true,', '"true" | "on" | "yes" | "1" => true,\n        "" => false,', AGENT),
    # What only a cluster shows.
    ("the scanner starts before its pod is cut off", K + "executor.rs", "        if gated {", "        if false {", K3S_CHOICE),
    ("a namespace admitting a privileged pod accepted", K + "choice.rs", "    if found != Isolation::Enforced {\n        return Err(format!(\n            \"The scans' namespace",
     "    if false {\n        return Err(format!(\n            \"The scans' namespace", K3S_CHOICE),
    ("a scan pod reaching the API server accepted", K + "choice.rs", "        if found != Isolation::Enforced {\n            return Err(format!(\n                \"An {} scan pod",
     "        if false {\n            return Err(format!(\n                \"An {} scan pod", K3S_CHOICE),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=1800))
