//! The fingerprint, the tool keys and the clip against Java's answers in `reference/fingerprints/` —
//! `FingerprintReferenceSetTest`'s hand-picked cases and its seeded corpus. No tolerance: one hash that
//! differs is an issue whose triage the switch to Rust would lose.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use serde_json::Value;
use vectispire_domain::fingerprint::{self, Input};
use vectispire_domain::{FindingType, ScanTarget, bounded_text, java, tool_keys};

/// A text as the set writes it: a string, null, or `{"utf16": [units]}` for one holding an unpaired
/// surrogate — read as Java's `getBytes(UTF_8)` would have written it (`java::from_utf16`).
fn text(node: &Value) -> Option<String> {
    match node {
        Value::Null => None,
        Value::String(text) => Some(text.clone()),
        Value::Object(units) => {
            let units: Vec<u16> = units["utf16"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| u16::try_from(u.as_u64().unwrap()).unwrap())
                .collect();
            Some(java::from_utf16(&units))
        }
        other => panic!("not a text: {other}"),
    }
}

fn target(node: &Value) -> ScanTarget {
    match (node.get("repository"), node.get("container")) {
        (Some(id), None) => ScanTarget::Repository(id.as_i64().unwrap()),
        (None, Some(id)) => ScanTarget::Container(id.as_i64().unwrap()),
        _ => panic!("not a target: {node}"),
    }
}

fn finding_type(node: &Value) -> FindingType {
    FindingType::from_wire_name(node.as_str()).unwrap()
}

/// `{"value": text}` or `{"refused": sentence}`, as the Java side wrote the answer.
fn answer<E: ToString>(result: Result<String, E>) -> Value {
    match result {
        Ok(value) => serde_json::json!({ "value": value }),
        Err(refused) => serde_json::json!({ "refused": refused.to_string() }),
    }
}

/// Java's answer with its texts read as `text` reads an input, so that a key holding a lone surrogate
/// compares as the string Rust can hold.
fn expected(node: &Value) -> Value {
    match node.get("value") {
        Some(value) => serde_json::json!({ "value": text(value) }),
        None => node.clone(),
    }
}

fn of(case: &Value) -> String {
    let (identifier, purl, name, path) =
        (text(&case["identifier"]), text(&case["purl"]), text(&case["package_name"]), text(&case["file_path"]));
    fingerprint::of(&Input {
        target: target(&case["target"]),
        finding_type: finding_type(&case["type"]),
        identifier: identifier.as_deref(),
        purl: purl.as_deref(),
        package_name: name.as_deref(),
        file_path: path.as_deref(),
    })
}

#[test]
fn every_hand_picked_case_answers_as_java_answers() {
    let cases = vectispire_testkit::read_json("fingerprints/cases.json");
    let mut differences = Vec::new();
    let mut ops = std::collections::BTreeMap::<String, usize>::new();
    for case in cases.as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let op = case["op"].as_str().unwrap();
        *ops.entry(op.to_owned()).or_default() += 1;
        let (ours, java) = match op {
            "of" => (Value::from(of(case)), case["fingerprint"].clone()),
            "of_tool" => {
                let (key, rule, path) = (text(&case["tool_key"]), text(&case["rule_id"]), text(&case["file_path"]));
                let result = fingerprint::of_tool(
                    target(&case["target"]),
                    finding_type(&case["type"]),
                    key.as_deref(),
                    rule.as_deref(),
                    path.as_deref(),
                );
                (answer(result), expected(&case["answer"]))
            }
            "plugin_key" => (answer(tool_keys::plugin(text(&case["id"]).as_deref())), expected(&case["answer"])),
            "imported_key" => (
                answer(tool_keys::imported(text(&case["source"]).as_deref(), text(&case["tool"]).as_deref())),
                expected(&case["answer"]),
            ),
            "fields" => {
                let fields: Vec<Option<String>> = case["fields"].as_array().unwrap().iter().map(text).collect();
                let fields: Vec<Option<&str>> = fields.iter().map(Option::as_deref).collect();
                (Value::from(fingerprint::sha256_fields(&fields)), case["hash"].clone())
            }
            "utf8" => {
                let bytes = text(&case["text"]).unwrap().into_bytes();
                (Value::from(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()), case["bytes"].clone())
            }
            "clip" => {
                let value = text(&case["value"]);
                let max = usize::try_from(case["max"].as_u64().unwrap()).unwrap();
                (serde_json::json!(bounded_text::clip(value.as_deref(), max)), case["clipped"].clone())
            }
            "too_long" => {
                let value = text(&case["value"]);
                let max = usize::try_from(case["max"].as_u64().unwrap()).unwrap();
                (
                    serde_json::json!(bounded_text::too_long(value.as_deref(), max, "The comment")),
                    case["message"].clone(),
                )
            }
            other => panic!("unknown op {other}"),
        };
        if ours != java {
            differences.push(format!("{name} ({op}): java {java} rust {ours}"));
        }
    }
    assert!(differences.is_empty(), "{} difference(s):\n{}", differences.len(), differences.join("\n"));
    // A file that lost a kind of case would pass vacuously on it.
    for op in ["of", "of_tool", "plugin_key", "imported_key", "fields", "utf8", "clip", "too_long"] {
        assert!(ops.get(op).copied().unwrap_or(0) > 0, "no {op} case in cases.json");
    }
}

#[test]
fn the_seeded_corpus_hashes_as_java_hashes_it() {
    let corpus = vectispire_testkit::read_json("fingerprints/corpus.json");
    let corpus = corpus.as_array().unwrap();
    assert!(corpus.len() >= 1000, "the corpus shrank to {}", corpus.len());
    let mut differences = Vec::new();
    let mut clipped = 0;
    for (index, case) in corpus.iter().enumerate() {
        let target = target(&case["target"]);
        let kind = finding_type(&case["type"]);
        let (identifier, purl, name, path) =
            (text(&case["identifier"]), text(&case["purl"]), text(&case["package_name"]), text(&case["file_path"]));
        let checks = [
            ("fingerprint", Value::from(of(case)), case["fingerprint"].clone()),
            ("plugin_key", answer(tool_keys::plugin(name.as_deref())), expected(&case["plugin_key"])),
            (
                "imported_key",
                answer(tool_keys::imported(purl.as_deref(), name.as_deref())),
                expected(&case["imported_key"]),
            ),
            (
                "tool_fingerprint",
                answer(fingerprint::of_tool(target, kind, purl.as_deref(), identifier.as_deref(), path.as_deref())),
                expected(&case["tool_fingerprint"]),
            ),
        ];
        for (what, ours, java) in checks {
            if ours != java {
                differences.push(format!("#{index} {what}: java {java} rust {ours}"));
            }
        }
        if let Some(max) = case.get("clip_max") {
            clipped += 1;
            let ours =
                serde_json::json!(bounded_text::clip(path.as_deref(), usize::try_from(max.as_u64().unwrap()).unwrap()));
            if ours != case["clipped"] {
                differences.push(format!("#{index} clip: java {} rust {ours}", case["clipped"]));
            }
        }
    }
    assert!(differences.is_empty(), "{} difference(s):\n{}", differences.len(), differences.join("\n"));
    assert!(clipped > 500, "only {clipped} clip cases");
}

/// Java's `toLowerCase(Locale.ROOT)` around the capital sigma, which Java decides with its word iterator.
#[test]
fn the_sigma_is_lowered_as_java_lowers_it() {
    let corpus = vectispire_testkit::read_json("fingerprints/lowercase.json");
    let corpus = corpus.as_array().unwrap();
    assert!(corpus.len() >= 3000);
    let differences: Vec<String> = corpus
        .iter()
        .filter_map(|case| {
            let (text, lower) = (case["text"].as_str().unwrap(), case["lower"].as_str().unwrap());
            let ours = java::to_lower_root(text);
            (ours != lower).then(|| format!("{text:?}: java {lower:?} rust {ours:?}"))
        })
        .collect();
    assert!(differences.is_empty(), "{} difference(s):\n{}", differences.len(), differences.join("\n"));
}
