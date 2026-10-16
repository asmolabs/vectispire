//! The IaC and SAST scans' containers, as the daemon receives them, against what the Java runner
//! sends — `reference/container/{iac,sast}-scan-create.json`, captured off the wire by
//! `ScannerCreateReferenceSetTest` with a sub-path, so the command line's form of it is pinned too.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;
use std::time::Duration;
use vectispire_container::{ContainerRun, ScannerLimits, create_body};
use vectispire_scanners::{iac, images, sast};

/// The Java test's limits: 2 GiB, 512 processes, 15 minutes, 3 CPUs (the stub daemon has eight).
fn reference_limits() -> ScannerLimits {
    ScannerLimits {
        memory: 2048 * 1024 * 1024,
        pids: 512,
        timeout: Duration::from_secs(900),
        nano_cpus: 3_000_000_000,
        output_bytes: 256 * 1024 * 1024,
    }
    .clamped_to(8)
}

fn without_nulls(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(_, field)| !field.is_null())
                .map(|(key, field)| (key.clone(), without_nulls(field)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(without_nulls).collect()),
        other => other.clone(),
    }
}

fn differences(path: &str, java: &Value, rust: &Value, out: &mut Vec<String>) {
    match (java, rust) {
        (Value::Object(java), Value::Object(rust)) => {
            for (key, value) in java {
                match rust.get(key) {
                    None => out.push(format!("{path}.{key}: the Java side sends {value}, this side nothing")),
                    Some(ours) => differences(&format!("{path}.{key}"), value, ours, out),
                }
            }
            for key in rust.keys().filter(|key| !java.contains_key(*key)) {
                out.push(format!("{path}.{key}: sent here, never by the Java side: {}", rust[key]));
            }
        }
        _ if java != rust => out.push(format!("{path}: java {java} rust {rust}")),
        _ => {}
    }
}

fn assert_same_create(reference: &str, request: impl Fn(&std::path::Path) -> ContainerRun) {
    let workspace = tempfile::tempdir().unwrap();
    let request = request(workspace.path());
    let owner = request.user.clone().expect("the workspace has an owner on this file system");
    let body = serde_json::to_string(&create_body(&request, &reference_limits())).unwrap();
    let body = body
        .replace(&workspace.path().display().to_string(), "{workspace}")
        .replace(&format!("\"{owner}\""), "\"{owner}\"");
    let ours = without_nulls(&serde_json::from_str(&body).unwrap());

    let reference = vectispire_testkit::read_json(reference);
    assert_eq!(reference["path"], "/containers/create", "created with no query: no name, no platform");
    let java = without_nulls(&reference["body"]);
    let mut found = Vec::new();
    differences("body", &java, &ours, &mut found);
    assert!(found.is_empty(), "the create request differs from the Java runner's:\n{}", found.join("\n"));
}

#[test]
fn the_iac_scan_creates_what_the_java_runner_creates() {
    assert_same_create("container/iac-scan-create.json", |root| iac::request(root, Some("deploy"), images::CHECKOV));
}

#[test]
fn the_sast_scan_creates_what_the_java_runner_creates() {
    assert_same_create("container/sast-scan-create.json", |root| sast::request(root, Some("service"), images::SEMGREP));
}
