//! The bounded output's read-back and the pull credentials against the Java runner's answers —
//! `reference/plugins/{archives,measurements,credentials}/`, written by `PluginRunsReferenceSetTest`.
//!
//! The archives are Java's bytes, base64, built there; the reader here must answer the same file, the same
//! refusal, the same "too large" read off the header before a byte of content.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use vectispire_container::bounded_output::{BoundedOutput, CollectedOutput, OutputFile, read_archive};
use vectispire_container::pull_credentials::{self, DockerConfig};

fn answers(relative: &str) -> Vec<Value> {
    serde_json::from_str(&vectispire_testkit::read(relative)).unwrap()
}

fn compare(area: &str, java: &[Value], rust: &[Value]) {
    assert_eq!(java.len(), rust.len());
    let differences: Vec<String> = java
        .iter()
        .zip(rust)
        .filter(|(java, rust)| java != rust)
        .map(|(java, rust)| format!("  java: {java}\n  rust: {rust}"))
        .collect();
    assert!(
        differences.is_empty(),
        "{area}: {} difference(s) with Java:\n{}",
        differences.len(),
        differences.join("\n")
    );
}

#[test]
fn the_archives_are_read_as_java_reads_them() {
    let java = answers("plugins/archives/answers.json");
    assert!(java.len() >= 30, "the reference set is there");
    let rust: Vec<Value> = java
        .iter()
        .map(|case| {
            let archive = STANDARD.decode(case["archive"].as_str().unwrap()).unwrap();
            let ceiling = case["ceiling"].as_u64().unwrap();
            let mut answer = json!({"name": case["name"], "archive": case["archive"], "ceiling": ceiling});
            match read_archive(&archive, "results.sarif", ceiling) {
                Ok(OutputFile::Read(bytes)) => answer["read"] = json!(STANDARD.encode(bytes)),
                Ok(OutputFile::Missing) => answer["missing"] = json!(true),
                Ok(OutputFile::NotRegular) => answer["notRegular"] = json!(true),
                Ok(OutputFile::TooLarge(size)) => answer["tooLarge"] = json!(size),
                Err(unreadable) => answer["unreadable"] = json!(unreadable.0),
            }
            answer
        })
        .collect();
    compare("archives", &java, &rust);
}

#[test]
fn the_holders_df_is_believed_as_java_believes_it() {
    let java = answers("plugins/measurements/answers.json");
    let bounded = BoundedOutput::new("/repo/output", 10 * 1024 * 1024, "holder", "results.sarif").unwrap();
    let rust: Vec<Value> = java
        .iter()
        .map(|case| {
            let printed = case["printed"].as_str().unwrap();
            let measured = CollectedOutput::measured(&bounded, printed, OutputFile::Missing).map(|measured| {
                json!({
                    "capacity": measured.capacity,
                    "availableBytes": measured.available_bytes,
                    "availableInodes": measured.available_inodes,
                    "full": measured.full(),
                })
            });
            json!({"printed": printed, "measured": measured})
        })
        .collect();
    compare("measurements", &java, &rust);
}

#[test]
fn the_credentials_a_pull_sends_are_docker_javas() {
    let inputs: Vec<Value> = answers("plugins/credentials/cases.json");
    let java = answers("plugins/credentials/answers.json");
    let rust: Vec<Value> = inputs
        .iter()
        .map(|case| {
            let config = DockerConfig::parse(case["config"].as_str().unwrap().as_bytes());
            let references: Vec<Value> = case["references"]
                .as_array()
                .unwrap()
                .iter()
                .map(|reference| {
                    let reference = reference.as_str().unwrap();
                    let mut each =
                        json!({"reference": reference, "registry": pull_credentials::registry_of(reference)});
                    let config = match &config {
                        Err(_) => {
                            each["unreadable"] = json!(true);
                            return each;
                        }
                        Ok(config) => config,
                    };
                    let Some(auth) = config.credentials_for(reference) else {
                        each["configuration"] = Value::Null;
                        return each;
                    };
                    let registry = pull_credentials::registry_of(reference);
                    let written = auth.configuration(&registry);
                    let decoded = serde_json::from_str::<Value>(&written).unwrap()["auths"][&registry]["auth"]
                        .as_str()
                        .map(|auth| String::from_utf8(STANDARD.decode(auth).unwrap()).unwrap())
                        .unwrap_or_default();
                    each["entryRegistry"] = json!(registry);
                    each["configuration"] = json!(written);
                    each["redacted"] = json!(auth.redact(&format!("cosign said: {written} {decoded}")));
                    each
                })
                .collect();
            json!({"name": case["name"], "references": references})
        })
        .collect();
    compare("credentials", &java, &rust);
}

#[test]
fn an_unreadable_configuration_is_refused_by_path_never_by_content() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("config.json"), r#"{"auths":{"r.io":{"auth":"!!!secret"}}}"#).unwrap();
    let refused = DockerConfig::load(directory.path()).unwrap_err().to_string();
    assert!(refused.contains(&directory.path().display().to_string()), "{refused}");
    assert!(!refused.contains("secret"), "{refused}");
    assert!(DockerConfig::load(&directory.path().join("absent")).is_ok(), "no file is no credential, not a refusal");
}
