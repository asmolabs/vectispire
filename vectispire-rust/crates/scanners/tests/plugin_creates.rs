//! A plugin's containers, as the daemon receives them, against what the Java runner sends —
//! `reference/plugins/creates/`, captured off the wire by `PluginRunsReferenceSetTest`: the holder of the bounded
//! output (its tmpfs volume, its `df` on stop), the plugin beside it (`VolumesFrom`, `fsize`), and cosign with the
//! signer's key and the registry login mounted read-only and `DOCKER_CONFIG` naming it.
//!
//! Field by field, as `create_request.rs` compares the secrets scan's: a field the Java side sends must be sent with
//! the same value, a field it leaves null must be left out, and nothing may be sent that it does not send.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use serde_json::Value;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;
use vectispire_container::bounded_output::BoundedOutput;
use vectispire_container::{
    ContainerResult, ContainerRun, ExtendedError, ExtendedResult, Extras, Mount, RegistryAccess, ScannerLimits,
    holder_body, tool_body,
};
use vectispire_domain::plugin_signature::PluginSignature;
use vectispire_scanners::plugins;

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

fn assert_same(what: &str, java: &Value, rust: &Value) {
    let mut found = Vec::new();
    differences(what, &without_nulls(java), &without_nulls(rust), &mut found);
    assert!(found.is_empty(), "{what} differs from the Java runner's:\n{}", found.join("\n"));
}

fn creates(file: &str) -> Vec<Value> {
    let recorded: Vec<Value> = serde_json::from_str(&vectispire_testkit::read(file)).unwrap();
    recorded
        .into_iter()
        .filter(|request| request["path"] == "/containers/create")
        .map(|request| request["body"].clone())
        .collect()
}

#[test]
fn the_holder_and_the_plugin_are_created_as_java_creates_them() {
    let java = creates("plugins/creates/bounded-output.json");
    let limits = reference_limits();
    let bounded =
        BoundedOutput::new("/repo/output", 256 * 1024 * 1024, plugins::OUTPUT_HOLDER, "results.sarif").unwrap();
    let holder = holder_body(
        &bounded,
        "1000:1000",
        &("1000".into(), "1000".into()),
        "plugin acme-lint",
        Duration::from_secs(120),
        &limits,
    );
    assert_same("the holder", &java[0], &serde_json::to_value(holder).unwrap());

    let mut run = ContainerRun::new(
        "registry.acme.internal/acme-lint@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        vec!["--out".into(), "/repo/output/results.sarif".into(), "/repo/source".into()],
        vec![Mount::read_only("{temporary}/workspace/source", "/repo/source")],
        "plugin acme-lint",
    );
    run.user = Some("1000:1000".into());
    run.timeout = Some(Duration::from_secs(120));
    let plugin = tool_body(&run, &limits, Some((&bounded, "holder-id")), None);
    assert_same("the plugin", &java[1], &serde_json::to_value(plugin).unwrap());
}

/// Records the verifier's request and answers what the stub daemon did: nothing, refused.
struct Recording(Mutex<Vec<(ContainerRun, Extras)>>);

impl plugins::PluginExecutor for Recording {
    fn output_bytes(&self) -> u64 {
        256 * 1024 * 1024
    }

    async fn run_with(&self, run: &ContainerRun, extras: &Extras) -> Result<ExtendedResult, ExtendedError> {
        self.0.lock().unwrap().push((run.clone(), extras.clone()));
        Ok(ExtendedResult {
            result: ContainerResult { stdout: String::new(), stderr: String::new(), exit_code: 0 },
            output: None,
        })
    }

    fn registry_access_for(&self, reference: &str) -> RegistryAccess {
        RegistryAccess { registry: vectispire_container::registry_of(reference), credentials_held: false }
    }
}

#[tokio::test]
async fn cosign_is_created_as_java_creates_it_with_the_key_and_the_login() {
    let java = creates("plugins/creates/cosign.json");
    let temporary = tempfile::tempdir().unwrap();
    let keys = temporary.path().join("workspace/plugins/acme-lint-signer");
    let key = vectispire_testkit::read("plugins/creates/cosign.pub");
    let signature = PluginSignature::new(None, None, Some(key.clone()));
    let recording = Recording(Mutex::new(Vec::new()));
    let reference =
        "registry.acme.internal/acme-lint@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    plugins::verify(&recording, reference, &signature, &keys, "1000:1000", "plugin acme-lint", plugins::COSIGN)
        .await
        .unwrap();

    assert_eq!(std::fs::read_to_string(keys.join("cosign.pub")).unwrap(), key, "the key is handed over as declared");
    let (run, extras) = recording.0.lock().unwrap().pop().unwrap();
    let login = extras.login.as_ref().unwrap();
    assert_eq!((login.reference.as_str(), login.directory.as_path()), (reference, keys.as_path()));
    // What the runner writes there for the run: a directory of its own, named as Java names it.
    let written = keys.join("registry-login{n}");
    let body = serde_json::to_string(&tool_body(&run, &reference_limits(), None, Some(Path::new(&written)))).unwrap();
    let body = body.replace(&temporary.path().display().to_string(), "{temporary}");
    assert_same("cosign", &java[0], &serde_json::from_str(&body).unwrap());
}
