//! The dependency parsers against the Java side's answers — `reference/dependencies/`, written by
//! `DependenciesReferenceSetTest`.
//!
//! - **Findings, byte for byte** as the agent's Jackson mapper writes them: every field of a finding is
//!   fingerprint material or gate material, and `null` — absent — where the Java side found no usable
//!   output.
//! - **SBOMs, value for value**: the SBOM is forwarded, not fingerprinted, and Jackson keeps a
//!   document's key order where a `serde_json::Value` sorts it; the values must be the same.
//! - **Check times**, both ways: the `checked` file two agents sharing one cache read from each other.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use vectispire_scanners::dependencies;
use vectispire_scanners::jackson;
use vectispire_scanners::vulnerability_database::{instant_text, parse_instant};

fn names(directory: &str) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(vectispire_testkit::reference_root().join(directory))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".json"))
        .collect();
    names.sort();
    names
}

#[test]
fn every_matcher_output_gives_the_java_findings_byte_for_byte() {
    let outputs = names("dependencies/matches");
    assert!(outputs.len() >= 20, "the reference set is there: {outputs:?}");
    let mut differences = Vec::new();
    for name in &outputs {
        let printed = vectispire_testkit::read(&format!("dependencies/matches/{name}"));
        let ours = jackson::to_wire_string(&dependencies::read_match_output(&printed)) + "\n";
        let java = vectispire_testkit::read(&format!("dependencies/findings/{name}"));
        if ours != java {
            let at = ours.bytes().zip(java.bytes()).position(|(a, b)| a != b).unwrap_or(ours.len().min(java.len()));
            let from = at.saturating_sub(80);
            differences.push(format!(
                "{name} (first difference at byte {at})\n  java: {}\n  rust: {}",
                java.get(from..(at + 80).min(java.len())).unwrap_or("?"),
                ours.get(from..(at + 80).min(ours.len())).unwrap_or("?")
            ));
        }
    }
    assert!(differences.is_empty(), "the findings differ — a fingerprint change:\n{}", differences.join("\n"));
}

#[test]
fn the_real_outputs_are_not_trivial() {
    // A reference set whose real outputs had silently become empty would pin nothing that matters.
    for (name, at_least) in [("01-polyglot.json", 50), ("03-alpine-image.json", 100)] {
        let printed = vectispire_testkit::read(&format!("dependencies/matches/{name}"));
        let findings = dependencies::read_match_output(&printed).unwrap();
        assert!(findings.len() >= at_least, "{name}: {}", findings.len());
        assert!(
            findings.iter().all(|finding| finding.identifier.starts_with("CVE-")
                || finding.identifier.starts_with("GHSA-")
                || finding.identifier.starts_with("GO-")
                || finding.identifier.starts_with("ALPINE-")),
            "{name}"
        );
    }
    let clean = dependencies::read_match_output(&vectispire_testkit::read("dependencies/matches/02-clean.json"));
    assert_eq!(clean, Some(Vec::new()), "a tree with no dependencies is analysed and clean");
}

#[test]
fn every_cataloguer_output_gives_the_java_sbom() {
    let outputs = names("dependencies/sboms");
    assert!(outputs.len() >= 10, "the reference set is there: {outputs:?}");
    let mut differences = Vec::new();
    for name in &outputs {
        let printed = vectispire_testkit::read(&format!("dependencies/sboms/{name}"));
        let ours = dependencies::read_sbom_output(&printed);
        let java: Option<serde_json::Value> =
            serde_json::from_str(&vectispire_testkit::read(&format!("dependencies/sbom/{name}"))).unwrap();
        if ours != java {
            differences.push(name.clone());
        }
    }
    assert!(differences.is_empty(), "the SBOM sent differs from the Java side's: {differences:?}");
}

#[test]
fn check_times_read_and_write_as_java_reads_and_writes_them() {
    for line in vectispire_testkit::read("dependencies/database/instants.txt").lines() {
        let mut fields = line.splitn(3, ' ');
        let (seconds, nanos, text) = (fields.next().unwrap(), fields.next().unwrap(), fields.next().unwrap());
        let at = std::time::UNIX_EPOCH + std::time::Duration::new(seconds.parse().unwrap(), nanos.parse().unwrap());
        assert_eq!(instant_text(at), text, "written as Instant.toString writes it");
        assert_eq!(parse_instant(text), Some(at), "read as Instant.parse reads it: {text}");
    }
}
