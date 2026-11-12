//! The scrub against the Java side's answers — `reference/failure-reason/`, written by
//! `FailureReasonReferenceSetTest` in `vectispire-common`. A text there is a string, or an array of
//! fragments read joined (the invented key blocks are cut inside their armour, for gitleaks).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;
use vectispire_protocol::failure_reason;

fn text(node: &Value) -> Option<String> {
    match node {
        Value::Null => None,
        Value::Array(fragments) => Some(fragments.iter().filter_map(Value::as_str).collect()),
        other => other.as_str().map(str::to_owned),
    }
}

#[test]
fn every_reason_is_scrubbed_as_the_java_side_scrubs_it() {
    let inputs = vectispire_testkit::read_json("failure-reason/inputs.json");
    let answers = vectispire_testkit::read_json("failure-reason/java-answers.json");
    let inputs = inputs.as_array().unwrap();
    assert_eq!(inputs.len(), answers.as_array().unwrap().len(), "one answer per input");
    let mut differences = Vec::new();
    for (input, answer) in inputs.iter().zip(answers.as_array().unwrap()) {
        let name = input["name"].as_str().unwrap();
        assert_eq!(answer["name"], name);
        let secrets: Vec<Option<String>> = input["secrets"].as_array().unwrap().iter().map(text).collect();
        let scrubbed = failure_reason::scrub(&text(&input["raw"]).unwrap(), secrets.iter().map(Option::as_deref));
        if scrubbed != answer["scrubbed"].as_str().unwrap() {
            differences.push(format!("{name}:\n  java: {:?}\n  rust: {scrubbed:?}", answer["scrubbed"]));
        }
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}
