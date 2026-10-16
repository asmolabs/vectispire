//! Result bodies written by this agent, read back by the Java side.
//!
//! `reference/artifacts/rust-written.json` is written here; `ScanArtifactsReferenceSetTest` in
//! `vectispire-common` reads each body with the agent's own mapper — the one the control plane builds
//! the same way — and writes it back. **The tree it writes must be the tree sent**: a step sent absent
//! and read as empty, or the reverse, would resolve or keep a backlog the scan never decided (decision
//! 0007), and that is a difference only the other side's reader can show.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::json;
use std::collections::BTreeSet;
use std::time::Duration;
use vectispire_protocol::{Failure, Findings, PluginStep, Project, Refusal, ScanArtifacts, Signature};

fn findings(values: Vec<serde_json::Value>) -> Findings {
    Findings::of(&values).unwrap()
}

fn digest(c: char) -> String {
    c.to_string().repeat(64)
}

/// The bodies, each named for what it pins.
fn cases() -> Vec<(&'static str, ScanArtifacts)> {
    vec![
        ("nothing-ran", ScanArtifacts::default()),
        (
            "everything-ran-and-found-nothing",
            ScanArtifacts {
                sbom: Some(serde_json::value::to_raw_value(&json!({"bomFormat": "CycloneDX", "components": []})).unwrap()),
                project: Some(Project { kind: Some("maven".into()), version: None }),
                languages: Some(BTreeSet::new()),
                dependencies: Some(Findings::default()),
                secrets: Some(Findings::default()),
                iac: Some(Findings::default()),
                sast: Some(Findings::default()),
                api_endpoints: Some(Findings::default()),
                api_contracts: Some(Findings::default()),
                plugins: vec![],
                failures: vec![],
                duration: Duration::from_secs(1),
            },
        ),
        (
            "some-steps-absent-with-their-failures",
            ScanArtifacts {
                languages: Some(["java".to_owned(), "python".to_owned()].into()),
                secrets: Some(findings(vec![json!({
                    "rule": "aws-access-token",
                    "description": "AWS — clé d'accès \"inventée\"\n",
                    "file": "src/main/resources/application.yaml",
                    "line": 12,
                    "fingerprint": "src/main/resources/application.yaml:aws-access-token:12"
                })])),
                failures: vec![
                    Failure { step: "dependencies".into(), reason: "syft exited 2".into() },
                    Failure { step: "sast".into(), reason: "semgrep: timed out after PT10M".into() },
                ],
                duration: Duration::from_millis(12_345),
                ..ScanArtifacts::default()
            },
        ),
        (
            "every-finding-type-and-plugin-state",
            ScanArtifacts {
                sbom: Some(
                    serde_json::value::to_raw_value(
                        &json!({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": "jackson", "version": "2.21.0"}]}),
                    )
                    .unwrap(),
                ),
                project: Some(Project { kind: Some("npm".into()), version: Some("1.4.0".into()) }),
                languages: Some(["javascript".to_owned()].into()),
                dependencies: Some(findings(vec![json!({
                    "identifier": "CVE-2026-0001",
                    "severity": "HIGH",
                    "packageName": "left-pad",
                    "installedVersion": "1.0.0",
                    "fixVersions": "1.0.1",
                    "description": null,
                    "referenceUrl": "https://example.org/CVE-2026-0001",
                    "purl": "pkg:npm/left-pad@1.0.0"
                })])),
                secrets: Some(Findings::default()),
                iac: Some(findings(vec![json!({
                    "checkId": "CKV_DOCKER_3",
                    "checkName": "Ensure that a user for the container has been created",
                    "file": "/Dockerfile",
                    "line": 1,
                    "guideline": null,
                    "resource": "/Dockerfile."
                })])),
                sast: Some(findings(vec![json!({
                    "ruleId": "javascript.lang.security.audit.eval",
                    "category": "security",
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "file": "src/index.js",
                    "line": 40,
                    "message": "eval() of a value a caller controls",
                    "owaspCategory": "A03:2021"
                })])),
                api_endpoints: Some(findings(vec![json!({
                    "method": "GET",
                    "path": "/admin/users",
                    "authRequired": false,
                    "authType": null,
                    "visibility": "PUBLIC",
                    "filePath": "src/routes.js",
                    "lineNumber": 7,
                    "framework": "express",
                    "operationId": null,
                    "summary": null,
                    "tags": null,
                    "sensitivePath": true
                })])),
                api_contracts: Some(findings(vec![json!({
                    "contractPath": "openapi.yaml",
                    "format": "openapi-3",
                    "title": "Shop",
                    "version": "1",
                    "endpointsCount": 3,
                    "declaredPaths": ["/a", "/b", "/c"]
                })])),
                plugins: vec![
                    PluginStep::Produced {
                        plugin_id: "a".into(),
                        manifest_digest: digest('a'),
                        tool_name: Some("tool".into()),
                        tool_version: Some("1".into()),
                        findings: findings(vec![json!({
                            "ruleId": "r1",
                            "severity": "LOW",
                            "file": "x.go",
                            "line": null,
                            "message": "m"
                        })]),
                        signature: Some(Signature::Waived),
                    },
                    PluginStep::Produced {
                        plugin_id: "b".into(),
                        manifest_digest: digest('b'),
                        tool_name: None,
                        tool_version: None,
                        findings: Findings::default(),
                        signature: None,
                    },
                    PluginStep::NotApplicable {
                        plugin_id: "c".into(),
                        manifest_digest: digest('c'),
                        languages: vec!["go".into(), "java".into()],
                    },
                    PluginStep::Absent { plugin_id: "d".into(), manifest_digest: digest('d'), reason: "exit 2".into() },
                    PluginStep::Refused {
                        plugin_id: "e".into(),
                        manifest_digest: digest('e'),
                        refusal: Refusal::SignatureUnverified,
                        reason: "no signature by the declared signer".into(),
                    },
                ],
                failures: vec![],
                duration: Duration::from_millis(3_723_500),
            },
        ),
    ]
}

#[test]
fn the_bodies_the_java_side_reads_back() {
    let bodies: Vec<serde_json::Value> = cases()
        .into_iter()
        .map(|(name, artifacts)| json!({ "name": name, "body": artifacts.to_body().unwrap() }))
        .collect();
    vectispire_testkit::expect("artifacts/rust-written.json", &(serde_json::to_string_pretty(&bodies).unwrap() + "\n"));
}

#[test]
fn a_body_is_valid_json_with_every_field_present() {
    for (name, artifacts) in cases() {
        let written: serde_json::Value = serde_json::from_str(&artifacts.to_body().unwrap()).unwrap();
        let fields: Vec<&str> = written.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(fields.len(), 12, "{name}: {fields:?}");
    }
}
