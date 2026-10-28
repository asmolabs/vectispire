//! The target and scan vocabulary against Java's answers in `reference/vocabulary/`
//! (`VocabularyReferenceSetTest`): the finding types and statuses, the SBOM readings, the licence blocklist,
//! the retention rules, and the digits `Integer.parseInt` reads.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use serde_json::{Value, json};
use vectispire_domain::dependency_graph::{DependencyGraph, Directness};
use vectispire_domain::finding_type::GateParticipation;
use vectispire_domain::instant::Instant;
use vectispire_domain::retention::{Candidate, RetentionPolicy, evidence, int_setting};
use vectispire_domain::sbom::{self, LicenseBlocklist};
use vectispire_domain::{FindingType, ScanStatus, ScanTarget, java};

fn instant(node: &Value) -> Instant {
    serde_json::from_value(node.clone()).unwrap()
}

fn directness_name(directness: Directness) -> &'static str {
    match directness {
        Directness::Direct => "DIRECT",
        Directness::Transitive => "TRANSITIVE",
        Directness::Unknown => "UNKNOWN",
    }
}

#[test]
fn every_sbom_is_read_as_java_reads_it() {
    let inputs = vectispire_testkit::read_json("vocabulary/sboms.json");
    let answers = vectispire_testkit::read_json("vocabulary/sbom-answers.json");
    let (inputs, answers) = (inputs.as_array().unwrap(), answers.as_array().unwrap());
    assert_eq!(inputs.len(), answers.len(), "sbom-answers.json is regenerated after sboms.json");
    let mut differences = Vec::new();
    for (input, java) in inputs.iter().zip(answers) {
        // A member written `null` is Jackson's NullNode: present, and not an object.
        let document = input.get("document");
        let artifacts = sbom::artifacts(document);
        let graph = DependencyGraph::new(document);
        let mut ours = json!({
            "name": input["name"],
            "is_catalogue": sbom::is_catalogue(document),
            "artifacts": artifacts.iter().map(|a| json!({
                "name": a.name, "version": a.version, "purl": a.purl, "licenses": a.licenses,
            })).collect::<Vec<_>>(),
            "distro": sbom::distro(document).map(|d| json!({ "id": d.id, "version": d.version, "label": d.label })),
            "graph_available": graph.is_available(),
            "direct_count": graph.direct_count(),
            "probes": input.get("probes").and_then(Value::as_array).into_iter().flatten().map(|probe| {
                directness_name(graph.of(probe[0].as_str(), probe[1].as_str(), probe[2].as_str()))
            }).collect::<Vec<_>>(),
        });
        if let Some(raw) = input.get("blocklist") {
            let violations = LicenseBlocklist::parse(raw.as_str()).violations(&artifacts);
            ours["violations"] = violations
                .iter()
                .map(|v| {
                    json!({ "license": v.license, "package_name": v.package_name,
                    "package_version": v.package_version, "purl": v.purl })
                })
                .collect();
        }
        if &ours != java {
            differences.push(format!("{}:\n  java {java}\n  rust {ours}", input["name"]));
        }
    }
    assert!(differences.is_empty(), "{} difference(s):\n{}", differences.len(), differences.join("\n"));
}

#[test]
fn the_words_and_the_rules_are_java_s() {
    let java = vectispire_testkit::read_json("vocabulary/answers.json");

    let types: Vec<Value> = FindingType::ALL
        .iter()
        .map(|t| {
            let gate = match t.gate_participation() {
                GateParticipation::Always => "ALWAYS",
                GateParticipation::OnRequest => "ON_REQUEST",
                GateParticipation::Never => "NEVER",
            };
            json!({ "wire_name": t.wire_name(), "gate": gate, "tool_scoped": t.tool_scoped(), "security": t.is_security() })
        })
        .collect();
    assert_eq!(Value::from(types), java["finding_types"]);
    let statuses: Vec<Value> =
        ScanStatus::ALL.iter().map(|s| json!({ "wire_name": s.wire_name(), "in_flight": s.is_in_flight() })).collect();
    assert_eq!(Value::from(statuses), java["scan_statuses"]);
    for probe in java["from_wire_name"].as_array().unwrap() {
        let value = probe["value"].as_str();
        assert_eq!(
            FindingType::from_wire_name(value).map(FindingType::wire_name),
            probe["finding_type"].as_str(),
            "{probe}"
        );
        assert_eq!(
            ScanStatus::from_wire_name(value).map(ScanStatus::wire_name),
            probe["scan_status"].as_str(),
            "{probe}"
        );
    }

    for case in java["blocklists"].as_array().unwrap() {
        let ours: Vec<String> = LicenseBlocklist::parse(case["raw"].as_str()).forbidden.into_iter().collect();
        assert_eq!(json!(ours), case["forbidden"], "{case}");
    }
    for case in java["int_settings"].as_array().unwrap() {
        assert_eq!(i64::from(int_setting(case["raw"].as_str(), 90)), case["value"].as_i64().unwrap(), "{case}");
    }
    let now = Instant { epoch_second: 1_792_238_400, nano: 500_000_000 };
    for case in java["evidence_cutoffs"].as_array().unwrap() {
        let days = i32::try_from(case["days"].as_i64().unwrap()).unwrap();
        assert_eq!(evidence::cutoff(days, now).map(|c| json!(c)).unwrap_or(Value::Null), case["cutoff"], "{case}");
    }

    let zeros: Vec<Value> = java::DIGIT_ZEROS.iter().map(|&z| Value::from(z)).collect();
    assert_eq!(Value::from(zeros), java["digit_zeros"], "Character.digit's runs");
}

#[test]
fn retention_purges_what_java_purges() {
    let java = vectispire_testkit::read_json("vocabulary/answers.json");
    let cases = java["retention"].as_array().unwrap();
    assert!(cases.len() >= 18);
    for case in cases {
        let policy = RetentionPolicy {
            keep_per_target: u32::try_from(case["keep_per_target"].as_u64().unwrap()).unwrap(),
            max_age: std::time::Duration::from_secs(case["max_age_days"].as_u64().unwrap() * 86_400),
        };
        let candidates: Vec<Candidate> = case["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| Candidate {
                scan_id: c["scan_id"].as_i64().unwrap(),
                target: match (c.get("repository"), c.get("container")) {
                    (Some(id), None) => ScanTarget::Repository(id.as_i64().unwrap()),
                    (None, Some(id)) => ScanTarget::Container(id.as_i64().unwrap()),
                    _ => panic!("{c}"),
                },
                created_at: instant(&c["created_at"]),
            })
            .collect();
        assert_eq!(policy.is_enabled(), case["enabled"].as_bool().unwrap(), "{case}");
        let ours = policy.prunable(&candidates, instant(&case["now"]));
        assert_eq!(json!(ours), case["prunable"], "policy {} / {} days", policy.keep_per_target, case["max_age_days"]);
    }
}
