//! The plugin decisions against the Java side's answers — `reference/plugins/`, written by
//! `PluginsReferenceSetTest` and `PluginRunsReferenceSetTest` from the committed `cases.json`.
//!
//! Each area compares case by case and lists every difference at once: a plugin is code somebody else wrote, and a
//! manifest believed here and refused there, a report read here and refused there, or a refusal reported as absent
//! is a confinement lost. A refusal whose words are Jackson's own (`not readable JSON: …`) is compared up to that
//! prefix, and a manifest the agent's mapper cannot read up to "unreadable" — the port does not reproduce
//! Jackson's messages.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use serde_json::{Value, json};
use vectispire_scanners::plugins;
use vectispire_scanners::sarif;

fn cases(relative: &str) -> Vec<Value> {
    serde_json::from_str(&vectispire_testkit::read(relative)).unwrap()
}

fn report(area: &str, differences: &[String]) {
    assert!(
        differences.is_empty(),
        "{area}: {} difference(s) with Java:\n{}",
        differences.len(),
        differences.join("\n")
    );
}

/// A text with Jackson's own words after "not readable JSON: " cut — to the end of the text, or of the JSON string
/// that carries them inside a step's serialised form.
fn without_jackson_detail(text: &str) -> String {
    match text.split_once(sarif::NOT_READABLE_JSON) {
        None => text.to_owned(),
        Some((before, after)) => match after.split_once("\"}") {
            Some((_, tail)) => format!("{before}{}…\"}}{tail}", sarif::NOT_READABLE_JSON),
            None => format!("{before}{}…", sarif::NOT_READABLE_JSON),
        },
    }
}

/// Two answers, the Jackson-worded refusals compared up to their prefix.
fn same(java: &Value, rust: &Value) -> bool {
    match (java, rust) {
        (Value::String(java), Value::String(rust)) if java.contains(sarif::NOT_READABLE_JSON) => {
            without_jackson_detail(java) == without_jackson_detail(rust)
        }
        (Value::Object(java), Value::Object(rust)) => {
            java.len() == rust.len()
                && java.iter().all(|(key, value)| rust.get(key).is_some_and(|ours| same(value, ours)))
        }
        (Value::Array(java), Value::Array(rust)) => {
            java.len() == rust.len() && java.iter().zip(rust).all(|(java, rust)| same(java, rust))
        }
        _ => java == rust,
    }
}

fn compare(area: &str, java: &[Value], rust: &[Value]) {
    assert_eq!(java.len(), rust.len(), "{area}: as many answers as cases");
    let differences: Vec<String> = java
        .iter()
        .zip(rust)
        .filter(|(java, rust)| !same(java, rust))
        .map(|(java, rust)| format!("  java: {java}\n  rust: {rust}"))
        .collect();
    report(area, &differences);
}

#[test]
fn the_sarif_reports_read_as_java_reads_them() {
    let inputs = cases("plugins/sarif/cases.json");
    let java = cases("plugins/sarif/answers.json");
    let rust: Vec<Value> = inputs
        .iter()
        .map(|input| {
            let name = input["name"].as_str().unwrap();
            let document = document(input);
            let max = input.get("maxBytes").and_then(Value::as_u64).unwrap_or(256 * 1024 * 1024);
            match sarif::read(document.as_bytes(), max, &["/repo/source"]) {
                Err(refused) => json!({"name": name, "refused": refused.0}),
                Ok(runs) => match plugins::findings(&runs, "plugin acme-lint") {
                    Err(failed) => json!({"name": name, "failed": failed.to_string()}),
                    Ok(None) => json!({"name": name, "absent": true}),
                    Ok(Some(read)) => json!({"name": name, "produced": {
                        "toolName": read.tool_name,
                        "toolVersion": read.tool_version,
                        "findings": serde_json::to_string(&read.findings).unwrap(),
                    }}),
                },
            }
        })
        .collect();
    compare("sarif", &java, &rust);
}

/// The case's document, or the one both sides build for a case too large to commit.
fn document(input: &Value) -> String {
    let Some(counts) = input.get("repeatedResults") else { return input["document"].as_str().unwrap().to_owned() };
    let runs: Vec<String> = counts
        .as_array()
        .unwrap()
        .iter()
        .map(|count| {
            let results = vec![r#"{"ruleId":"R","kind":"pass"}"#; usize::try_from(count.as_u64().unwrap()).unwrap()];
            format!(r#"{{"tool":{{"driver":{{"name":"acme-lint"}}}},"results":[{}]}}"#, results.join(","))
        })
        .collect();
    format!(r#"{{"version":"2.1.0","runs":[{}]}}"#, runs.join(","))
}

#[test]
fn the_images_relocate_as_java_relocates_them() {
    let inputs = cases("plugins/images/cases.json");
    let java = cases("plugins/images/answers.json");
    let rust: Vec<Value> = inputs
        .iter()
        .map(|input| {
            let reference = input["reference"].as_str().unwrap();
            let mirror = input["mirror"].as_str();
            let mut answer = serde_json::Map::new();
            answer.insert("reference".into(), json!(reference));
            answer.insert("mirror".into(), input["mirror"].clone());
            match vectispire_domain::plugin_image::relocate(reference, mirror) {
                Ok(relocated) => answer.insert("relocated".into(), json!(relocated)),
                Err(refused) => answer.insert("refused".into(), json!(refused.0)),
            };
            match plugins::Settings::new(mirror, true) {
                Ok(settings) => answer.insert("settings".into(), json!(settings.registry_mirror)),
                Err(refused) => answer.insert("settingsRefused".into(), json!(refused.0)),
            };
            answer.insert("registry".into(), json!(vectispire_container::registry_of(reference)));
            Value::Object(answer)
        })
        .collect();
    compare("images", &java, &rust);
}

#[test]
fn the_manifests_are_believed_as_java_believes_them() {
    let inputs = cases("plugins/manifests/cases.json");
    let java = cases("plugins/manifests/answers.json");
    let rust: Vec<Value> = inputs
        .iter()
        .map(|input| {
            let name = input["name"].as_str().unwrap();
            let Some(manifest) = plugins::manifest_of(&input["manifest"]) else {
                return json!({"name": name, "unreadable": true});
            };
            let digest = manifest.digest();
            if let Err(refused) = manifest.validated() {
                return json!({"name": name, "digest": digest, "refused": refused.0});
            }
            use vectispire_domain::plugin_manifest::{OUTPUT, SOURCE};
            json!({
                "name": name,
                "digest": digest,
                "output": manifest.output,
                "command": manifest.command(SOURCE, &format!("{OUTPUT}/{}", manifest.output)),
                "exitCodes": manifest.exit_codes,
                "languages": manifest.languages.iter().map(|language| language.wire_name()).collect::<Vec<_>>(),
                "network": manifest.network,
                "timeoutSeconds": manifest.timeout_seconds,
                "schemaVersion": manifest.schema_version,
                "signature": manifest.signature.as_ref().map(|signature| json!({
                    "form": signature.form().name(),
                    "digestFields": signature.digest_fields(),
                })),
            })
        })
        .collect();
    compare("manifests", &java, &rust);
}

// ---------------------------------------------------------------------------------------------------------------
// The steps, end to end, through a stand-in executor.

mod steps {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::Path;
    use std::sync::Mutex;
    use vectispire_container::bounded_output::{CollectedOutput, OutputFile};
    use vectispire_container::{ContainerResult, ContainerRun, ExtendedError, ExtendedResult, Extras, RegistryAccess};
    use vectispire_domain::language::Language;
    use vectispire_protocol::PluginRef;

    /// The executor the scenario describes: cosign told apart by its label, the plugin's run answering what the
    /// holder's archive and `df` would have said.
    pub struct StandIn {
        pub scenario: Value,
        pub output_bytes: u64,
        pub requests: Mutex<Vec<(ContainerRun, Extras)>>,
    }

    impl StandIn {
        fn plugin(&self, label: &str) -> Value {
            self.scenario["plugins"]
                .as_array()
                .unwrap()
                .iter()
                .find(|plugin| {
                    let id = plugin["manifest"]["id"].as_str().unwrap();
                    label == format!("plugin {id}") || label == format!("plugin {id} signature")
                })
                .cloned()
                .unwrap()
        }
    }

    impl plugins::PluginExecutor for StandIn {
        fn output_bytes(&self) -> u64 {
            self.output_bytes
        }

        async fn run_with(&self, run: &ContainerRun, extras: &Extras) -> Result<ExtendedResult, ExtendedError> {
            self.requests.lock().unwrap().push((run.clone(), extras.clone()));
            let plugin = self.plugin(&run.label);
            let failed = |message: &Value| ExtendedError::Failed {
                label: run.label.clone(),
                message: message.as_str().unwrap().to_owned(),
            };
            let result = |answer: &Value| ContainerResult {
                stdout: String::new(),
                stderr: answer["stderr"].as_str().unwrap().to_owned(),
                exit_code: answer["exit"].as_i64().unwrap(),
            };
            if run.label.ends_with(" signature") {
                let cosign = &plugin["cosign"];
                if let Some(message) = cosign.get("throws") {
                    return Err(failed(message));
                }
                return Ok(ExtendedResult { result: result(cosign), output: None });
            }
            let answer = &plugin["run"];
            if let Some(message) = answer.get("throws") {
                return Err(failed(message));
            }
            if answer.get("noOutput").is_some() {
                return Ok(ExtendedResult { result: result(answer), output: None });
            }
            let file = &answer["file"];
            let read = match file["kind"].as_str().unwrap() {
                "read" => OutputFile::Read(file["content"].as_str().unwrap().as_bytes().to_vec()),
                "missing" => OutputFile::Missing,
                "notRegular" => OutputFile::NotRegular,
                "tooLarge" => OutputFile::TooLarge(file["size"].as_u64().unwrap()),
                other => panic!("{other}"),
            };
            let full = answer["full"].as_bool().unwrap();
            Ok(ExtendedResult {
                result: result(answer),
                output: Some(CollectedOutput {
                    capacity: extras.output.as_ref().unwrap().bytes,
                    available_bytes: if full { 0 } else { 1 << 20 },
                    available_inodes: if full { 0 } else { 100 },
                    file: read,
                }),
            })
        }

        fn registry_access_for(&self, reference: &str) -> RegistryAccess {
            let held = self.scenario["plugins"]
                .as_array()
                .unwrap()
                .iter()
                .find_map(|plugin| plugin["cosign"].get("credentialsHeld").and_then(Value::as_bool))
                .unwrap_or(false);
            RegistryAccess { registry: vectispire_container::registry_of(reference), credentials_held: held }
        }
    }

    pub struct Provider(pub Value);

    impl plugins::PluginProvider for Provider {
        async fn manifest(&self, reference: &PluginRef) -> Result<Value, String> {
            let plugin = self.0["plugins"]
                .as_array()
                .unwrap()
                .iter()
                .find(|plugin| plugin["manifest"]["id"] == reference.id.as_str())
                .unwrap();
            let mut manifest = plugin["manifest"].clone();
            match plugin["fetch"].as_str().unwrap() {
                "ok" => Ok(manifest),
                "null" => Ok(Value::Null),
                "throws" => Err(format!("Plugin {} refused: HTTP 404", reference.id)),
                // `IllegalStateException()` has no message: Java writes its `toString`.
                "throwsBare" => Err("java.lang.IllegalStateException".to_owned()),
                "otherId" => {
                    manifest["id"] = json!("someone-else");
                    Ok(manifest)
                }
                "otherDigest" => {
                    manifest["name"] = json!("Another");
                    Ok(manifest)
                }
                other => panic!("{other}"),
            }
        }
    }

    fn owner_1000(_: &Path) -> Option<String> {
        Some("1000:1000".to_owned())
    }
    fn owner_none(_: &Path) -> Option<String> {
        None
    }
    fn owner_root(_: &Path) -> Option<String> {
        Some("0:0".to_owned())
    }

    /// A request as the port forms it, the workspace written as a placeholder — the shape Java records.
    fn shape(run: &ContainerRun, extras: &Extras, root: &Path) -> Value {
        let root = root.display().to_string();
        let local = |text: &str| text.replace(&root, "{workspace}");
        json!({
            "image": run.image,
            "command": run.command.iter().map(|argument| local(argument)).collect::<Vec<_>>(),
            "mounts": run.mounts.iter().map(|mount| json!({
                "source": local(&mount.source), "target": mount.target, "readOnly": mount.read_only,
            })).collect::<Vec<_>>(),
            "label": run.label,
            "network": run.network,
            "asRoot": run.as_root,
            "timeoutSeconds": run.timeout.map(|timeout| timeout.as_secs()),
            "user": run.user,
            "output": extras.output.as_ref().map(|output| json!({
                "target": output.target, "bytes": output.bytes, "holderImage": output.holder_image,
                "file": output.file, "inodes": output.inodes,
            })),
            "login": extras.login.as_ref().map(|login| json!({
                "reference": login.reference, "directory": local(&login.directory.display().to_string()),
            })),
        })
    }

    pub async fn scenario(scenario: &Value) -> Value {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path();
        if scenario["root"].as_bool().unwrap() {
            std::fs::create_dir_all(root.join("source/app")).unwrap();
        }
        let settings = &scenario["settings"];
        let settings =
            plugins::Settings::new(settings["mirror"].as_str(), settings["signatureRequired"].as_bool().unwrap())
                .unwrap();
        let owner: fn(&Path) -> Option<String> = match scenario["owner"].as_str() {
            None => owner_none,
            Some("0:0") => owner_root,
            Some("1000:1000") => owner_1000,
            Some(other) => panic!("{other}"),
        };
        let executor = StandIn {
            scenario: scenario.clone(),
            output_bytes: scenario.get("outputBytes").and_then(Value::as_u64).unwrap_or(256 * 1024 * 1024),
            requests: Mutex::new(Vec::new()),
        };
        let scanner = plugins::PluginScanner::with_owners(&executor, settings, owner);
        let references: Vec<PluginRef> = scenario["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .map(|plugin| PluginRef {
                id: plugin["manifest"]["id"].as_str().unwrap().to_owned(),
                digest: plugin
                    .get("digest")
                    .and_then(Value::as_str)
                    .map_or_else(|| plugins::digest_of(&plugin["manifest"]).unwrap(), str::to_owned),
                runs_unsigned: plugin["runsUnsigned"].as_bool().unwrap(),
            })
            .collect();
        let found: BTreeSet<Language> = scenario["census"]["found"]
            .as_array()
            .unwrap()
            .iter()
            .map(|language| Language::from_wire_name(language.as_str().unwrap()).unwrap())
            .collect();
        let complete = scenario["census"]["complete"].as_bool().unwrap();
        let source = root.join("source");
        let steps =
            plugins::run_steps(&scanner, &Provider(scenario.clone()), &references, root, Some(&source), |declared| {
                plugins::applies(&found, complete, declared)
            })
            .await;
        let root_text = root.display().to_string();
        let requests = executor.requests.lock().unwrap();
        json!({
            "name": scenario["name"],
            "steps": steps.iter().map(|step| serde_json::to_string(step).unwrap().replace(&root_text, "{workspace}")).collect::<Vec<_>>(),
            "runs": requests.iter().map(|(run, extras)| shape(run, extras, root)).collect::<Vec<_>>(),
        })
    }
}

#[tokio::test]
async fn each_plugin_ends_in_the_state_java_puts_it_in() {
    let inputs = cases("plugins/steps/cases.json");
    let java = cases("plugins/steps/answers.json");
    let mut rust = Vec::new();
    for scenario in &inputs {
        rust.push(steps::scenario(scenario).await);
    }
    compare("steps", &java, &rust);
}
