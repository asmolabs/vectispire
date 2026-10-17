//! Result bodies read as the Java control plane reads them — `reference/artifacts/java-read.json`, written by
//! `AgentWireReferenceSetTest` in `vectispire-core` with `CoreConfiguration`'s own mapper.
//!
//! **Each case is a body and what Java made of it**: refused, `null`, or read — and then, step by step,
//! present or absent, and every field of every finding as the Java record holds it. A step Java read as
//! absent and Rust as empty, or the reverse, resolves or keeps a backlog the scan never decided (decision
//! 0007); a body one side refuses and the other ingests is a scan whose findings exist on one control plane
//! only. Texts are compared as their UTF-8 bytes, which is how Java records them: a lone surrogate is `?`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine;
use serde_json::{Value, json};
use vectispire_protocol::{
    ApiVisibility, Listed, Received, ReceivedStep, Refusal, ScanArtifacts, Signature, Unreadable,
};

fn case_body(case: &Value) -> Vec<u8> {
    if let Some(body) = case["body"].as_str() {
        return body.as_bytes().to_vec();
    }
    if let Some(encoded) = case["body_base64"].as_str() {
        return base64::engine::general_purpose::STANDARD.decode(encoded).unwrap();
    }
    generate(&case["generated"])
}

/// `AgentWireReferenceSetTest.generate`, spelled the same way.
fn generate(generator: &Value) -> Vec<u8> {
    let count = usize::try_from(generator["count"].as_u64().unwrap()).unwrap();
    let unit = generator["unit"].as_str().unwrap_or_default();
    let body = match generator["kind"].as_str().unwrap() {
        "nested-unknown" => format!("{{\"later\":{}{},\"secrets\":[]}}", "[".repeat(count), "]".repeat(count)),
        "nested-sbom" => format!("{{\"sbom\":{}1{}}}", "{\"a\":".repeat(count), "}".repeat(count)),
        "nested-finding-field" => {
            format!("{{\"secrets\":[{{\"rule\":\"r\",\"later\":{}{}}}]}}", "[".repeat(count), "]".repeat(count))
        }
        "description" => format!("{{\"secrets\":[{{\"rule\":\"r\",\"description\":\"{}\"}}]}}", unit.repeat(count)),
        "unknown-text" => format!("{{\"later\":\"{}\",\"secrets\":[]}}", unit.repeat(count)),
        "sbom-text" => format!("{{\"sbom\":{{\"name\":\"{}\"}}}}", unit.repeat(count)),
        "unknown-integer" => format!("{{\"later\":{},\"secrets\":[]}}", "1".repeat(count)),
        "unknown-negative-integer" => format!("{{\"later\":-{},\"secrets\":[]}}", "1".repeat(count)),
        "unknown-decimal" => format!("{{\"later\":1.{},\"secrets\":[]}}", "1".repeat(count)),
        "unknown-exponent" => format!("{{\"later\":1e{},\"secrets\":[]}}", "1".repeat(count)),
        "unknown-key" => format!("{{\"{}\":1,\"secrets\":[]}}", "k".repeat(count)),
        "many-findings" => format!(
            "{{\"secrets\":[{}]}}",
            vec!["{\"rule\":\"r\",\"description\":\"d\",\"file\":\"f\",\"line\":1,\"fingerprint\":\"x\"}"; count]
                .join(",")
        ),
        other => panic!("no generator {other}"),
    };
    body.into_bytes()
}

fn list<T>(step: Option<&Listed<T>>, each: impl Fn(&T) -> Value) -> Value {
    match step {
        None => Value::Null,
        Some(items) => Value::Array(items.iter().map(|item| item.as_ref().map_or(Value::Null, &each)).collect()),
    }
}

fn severity(value: Option<vectispire_domain::severity::Severity>) -> Value {
    value.map_or(Value::Null, |severity| json!(severity.wire_name().to_uppercase()))
}

fn utf16_length(text: Option<&String>) -> Value {
    text.map_or(Value::Null, |text| json!(format!("length {}", text.encode_utf16().count())))
}

/// The same summary as `AgentWireReferenceSetTest.summary`, from what Rust read.
fn summary(read: &Received<'_>, whole: bool) -> Value {
    let sbom = match &read.sbom {
        None => Value::Null,
        Some(_) if !whole => json!("present"),
        // Java never holds a present `null`: the record filters it. Said so, so that it cannot pass for absent.
        Some(raw) if raw.get() == "null" => json!("a present null"),
        Some(raw) => serde_json::from_str(raw.get()).unwrap(),
    };
    let plugins: Vec<Value> = read
        .plugins
        .iter()
        .map(|step| match step {
            ReceivedStep::Produced { plugin_id, manifest_digest, tool_name, tool_version, findings, signature } => json!({
                "state": "produced", "pluginId": plugin_id, "manifestDigest": manifest_digest, "toolName": tool_name,
                "toolVersion": tool_version,
                "findings": list(Some(findings), |f| json!({"ruleId": f.rule_id, "severity": severity(f.severity), "file": f.file,
                    "line": f.line, "message": f.message})),
                "signature": signature.map(|s| match s {
                    Signature::Verified => "verified",
                    Signature::Waived => "waived",
                    Signature::NotRequired => "not_required",
                }),
            }),
            ReceivedStep::NotApplicable { plugin_id, manifest_digest, languages } => json!({
                "state": "not_applicable", "pluginId": plugin_id, "manifestDigest": manifest_digest, "languages": languages,
            }),
            ReceivedStep::Absent { plugin_id, manifest_digest, reason } => json!({
                "state": "absent", "pluginId": plugin_id, "manifestDigest": manifest_digest, "reason": reason,
            }),
            ReceivedStep::Refused { plugin_id, manifest_digest, refusal, reason } => json!({
                "state": "refused", "pluginId": plugin_id, "manifestDigest": manifest_digest,
                "refusal": refusal.map(|r| match r {
                    Refusal::Unsigned => "unsigned",
                    Refusal::SignatureUnverified => "signature_unverified",
                    Refusal::RegistryAuthenticationRequired => "registry_authentication_required",
                }),
                "reason": reason,
            }),
        })
        .collect();
    let mut summary = json!({
        "sbom": sbom,
        "project": read.project.as_ref().map(|p| json!({"type": p.kind, "version": p.version})),
        "languages": read.languages.as_ref().map(|names| names.iter().collect::<Vec<_>>()),
        "dependencies": list(read.dependencies.as_ref(), |d| json!({"identifier": d.identifier, "severity": severity(d.severity),
            "packageName": d.package_name, "installedVersion": d.installed_version, "fixVersions": d.fix_versions,
            "description": d.description, "referenceUrl": d.reference_url, "purl": d.purl})),
        "secrets": list(read.secrets.as_ref(), |f| json!({"rule": f.rule,
            "description": if whole { json!(f.description) } else { utf16_length(f.description.as_ref()) },
            "file": f.file, "line": f.line, "fingerprint": f.fingerprint})),
        "iac": list(read.iac.as_ref(), |f| json!({"checkId": f.check_id, "checkName": f.check_name, "file": f.file, "line": f.line,
            "guideline": f.guideline, "resource": f.resource})),
        "sast": list(read.sast.as_ref(), |f| json!({"ruleId": f.rule_id, "category": f.category, "severity": severity(f.severity),
            "confidence": f.confidence, "file": f.file, "line": f.line, "message": f.message, "owaspCategory": f.owasp_category})),
        "apiEndpoints": list(read.api_endpoints.as_ref(), |e| json!({"method": e.method, "path": e.path,
            "authRequired": e.auth_required, "authType": e.auth_type,
            "visibility": match e.visibility { ApiVisibility::Public => "PUBLIC", ApiVisibility::Internal => "INTERNAL",
                ApiVisibility::Unknown => "UNKNOWN" },
            "filePath": e.file_path, "lineNumber": e.line_number, "framework": e.framework, "operationId": e.operation_id,
            "summary": e.summary, "tags": e.tags})),
        "apiContracts": list(read.api_contracts.as_ref(), |c| json!({"contractPath": c.contract_path, "format": c.format,
            "title": c.title, "version": c.version, "endpointsCount": c.endpoints_count, "declaredPaths": c.declared_paths})),
        "plugins": plugins,
        "failures": list(Some(&read.failures), |f| json!({"step": f.step, "reason": f.reason})),
        "duration": read.duration.map(|d| json!({"seconds": d.seconds, "nanos": d.nanos})),
        "observedNothing": read.observed_nothing(),
    });
    if !whole {
        for step in [
            "languages",
            "dependencies",
            "secrets",
            "iac",
            "sast",
            "apiEndpoints",
            "apiContracts",
            "plugins",
            "failures",
        ] {
            if let Some(array) = summary[step].as_array() {
                summary[step] = json!({"count": array.len(), "first": array.first().cloned().unwrap_or(Value::Null)});
            }
        }
    }
    summary
}

#[test]
fn every_body_is_read_as_the_java_control_plane_reads_it() {
    let reference = vectispire_testkit::read_json("artifacts/java-read.json");
    let cases = reference["cases"].as_array().unwrap();
    assert!(cases.len() > 450, "{} cases", cases.len());
    let mut differences = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let body = case_body(case);
        let whole = case.get("generated").is_none();
        let outcome = match ScanArtifacts::read(&body) {
            Ok(read) => json!({"outcome": "read", "read": summary(&read, whole)}),
            Err(Unreadable::Null) => json!({"outcome": "null"}),
            Err(Unreadable::Refused(reason)) => json!({"outcome": "refused", "reason": reason}),
        };
        let expected = match case["outcome"].as_str().unwrap() {
            "read" => json!({"outcome": "read", "read": case["read"]}),
            "null" => json!({"outcome": "null"}),
            _ => json!({"outcome": "refused", "reason": outcome.get("reason").cloned().unwrap_or(Value::Null)}),
        };
        if outcome != expected {
            differences.push(format!("{name}:\n  java: {}\n  rust: {}", short(&expected, case), short(&outcome, case)));
        }
    }
    assert!(
        differences.is_empty(),
        "{} of {} cases differ:\n{}",
        differences.len(),
        cases.len(),
        differences.join("\n")
    );
}

fn short(outcome: &Value, case: &Value) -> String {
    let text = if outcome["outcome"] == "refused" && case["outcome"] == "refused" {
        format!("refused ({})", case["error"])
    } else {
        outcome.to_string()
    };
    text.chars().take(600).collect()
}

#[test]
fn absent_and_empty_arrive_apart() {
    let read = ScanArtifacts::read(br#"{"secrets":[],"sast":null,"iac":[null]}"#).unwrap();
    assert_eq!(read.secrets.as_deref().map(<[_]>::len), Some(0), "ran and found nothing");
    assert!(read.sast.is_none() && read.dependencies.is_none(), "null and missing are absent");
    assert_eq!(read.iac.as_deref().map(<[_]>::len), Some(1), "a null finding is kept for ingestion to decide");
    assert!(!read.observed_nothing());
}

#[test]
fn the_sbom_is_borrowed_from_the_body_unless_the_body_was_rewritten() {
    let body = br#"{"sbom":{"bomFormat":"CycloneDX","components":[]},"secrets":[]}"#;
    let read = ScanArtifacts::read(body).unwrap();
    assert!(matches!(read.sbom, Some(std::borrow::Cow::Borrowed(_))));
    let rewritten = ScanArtifacts::read(br#"{"sbom":{"n":"\uD800"}}"#).unwrap();
    assert_eq!(rewritten.sbom.as_ref().map(|raw| raw.get()), Some(r#"{"n":"?"}"#));
}
