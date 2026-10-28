//! `TeamRules` against Java's answers in `reference/teams/java-answers.json` (`TeamRulesReferenceSetTest`, in
//! `vectispire-common`): names, descriptions and target kinds, straddling the limits with emoji since a length is
//! UTF-16 units. Every difference is collected and reported at once.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use serde_json::{Value, json};
use vectispire_domain::bounded_text::Refused;
use vectispire_domain::team_rules;

fn outcome(result: Result<Option<String>, Refused>) -> Value {
    match result {
        Ok(value) => json!({ "value": value }),
        Err(Refused(message)) => json!({ "error": message }),
    }
}

/// Java's answer without its input, in the shape `outcome` writes: `value` (possibly `null`) or `error`.
fn expected(answer: &Value) -> Value {
    match answer.get("error") {
        Some(error) => json!({ "error": error }),
        None => json!({ "value": answer["value"] }),
    }
}

#[test]
fn team_rules_answer_as_java_does() {
    let answers = vectispire_testkit::read_json("teams/java-answers.json");
    type Rule = fn(Option<&str>) -> Result<Option<String>, Refused>;
    let rules: [(&str, Rule); 3] = [
        ("names", |input| team_rules::validate_name(input).map(Some)),
        ("descriptions", |input| Ok(team_rules::trim_description(input))),
        ("kinds", |input| team_rules::validate_target_kind(input).map(Some)),
    ];

    let mut differences = Vec::new();
    for (section, rule) in rules {
        let cases = answers[section].as_array().unwrap();
        assert!(cases.len() >= 10, "{section}: the reference set is thinner than it was written");
        for case in cases {
            let got = outcome(rule(case["input"].as_str()));
            if got != expected(case) {
                differences.push(format!("{section} {}: Java {}, Rust {got}", case["input"], expected(case)));
            }
        }
    }
    assert!(differences.is_empty(), "{} differences:\n{}", differences.len(), differences.join("\n"));
}
