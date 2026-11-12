//! The targets module's pure rules against Java's answers in `reference/targets/rules.json`
//! (`TargetRulesReferenceSetTest`, in `vectispire-core`, written before this port): bounded fields, the
//! repository URL's identity and names, the identity guard, image references, tiers, agent labels, list windows,
//! the clone host allow-list, the schedule in force and Java's case-insensitive order. Every difference is
//! collected and reported at once.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use serde_json::{Value, json};
use vectispire_domain::agent_labels;
use vectispire_domain::asset_tier::AssetTier;
use vectispire_domain::bounded_text;
use vectispire_domain::cron::crontab;
use vectispire_domain::git_host_allowlist::GitHostAllowlist;
use vectispire_domain::image_reference::ImageReference;
use vectispire_domain::java;
use vectispire_domain::list_window::ListWindow;
use vectispire_domain::repository_identity::RepositoryIdentity;
use vectispire_domain::repository_url;
use vectispire_domain::schedules;

fn rules() -> Value {
    vectispire_testkit::read_json("targets/rules.json")
}

fn text(value: &Value) -> Option<&str> {
    value.as_str()
}

fn outcome<T: Into<Value>>(result: Result<T, String>) -> Value {
    match result {
        Ok(value) => json!({ "value": value.into() }),
        Err(refused) => json!({ "refused": refused }),
    }
}

fn check(differences: &mut Vec<String>, what: &str, case: &Value, expected: &Value, got: &Value) {
    if expected != got {
        differences.push(format!("{what} {case}: Java {expected}, Rust {got}"));
    }
}

#[test]
fn every_rule_answers_as_java_does() {
    let rules = rules();
    let mut differences = Vec::new();
    let mut checked = 0usize;

    for case in rules["boundedText"].as_array().unwrap() {
        let input = text(&case["input"]);
        let required = bounded_text::required(input, 5, "A name").map_err(|refused| refused.0);
        let optional = bounded_text::optional(input, 5, "The description").map_err(|refused| refused.0);
        check(&mut differences, "required", case, &case["required"], &outcome(required));
        check(&mut differences, "optional", case, &case["optional"], &outcome(optional));
        if let Some(input) = input {
            let within = bounded_text::within(input, 5, "The URL").map(str::to_owned).map_err(|refused| refused.0);
            check(&mut differences, "within", case, &case["within"], &outcome(within));
        }
        checked += 1;
    }

    for case in rules["repositoryUrl"].as_array().unwrap() {
        let url = case["url"].as_str().unwrap();
        let got = json!({
            "url": url,
            "identity": repository_url::identity(url),
            "carriesCredential": repository_url::carries_credential(url),
            "shortName": repository_url::short_name(url),
            "displayNameUnnamed": repository_url::display_name(None, url),
            "displayNameBlank": repository_url::display_name(Some("  "), url),
            "displayNameNamed": repository_url::display_name(Some("  The API "), url),
            "displayNameNbsp": repository_url::display_name(Some("\u{a0}x\u{a0}"), url),
        });
        check(&mut differences, "repository URL", &case["url"], case, &got);
        checked += 1;
    }

    for case in rules["maskedForm"].as_array().unwrap() {
        let got =
            repository_url::is_masked_form_of(case["submitted"].as_str().unwrap(), case["stored"].as_str().unwrap());
        check(&mut differences, "masked form", case, &case["masked"], &json!(got));
        checked += 1;
    }

    for case in rules["repositoryIdentity"].as_array().unwrap() {
        let identity =
            RepositoryIdentity::of(case["url"].as_str().unwrap(), text(&case["branch"]), text(&case["subPath"]));
        let got = identity.map_or(Value::Null, |identity| {
            json!({
                "repository": identity.repository,
                "branch": identity.branch,
                "subPath": identity.sub_path,
                "guard": identity.guard(),
            })
        });
        check(&mut differences, "identity", case, &case["identity"], &got);
        checked += 1;
    }

    for case in rules["imageReference"].as_array().unwrap() {
        let reference = ImageReference::new(text(&case["registry"]), text(&case["imageName"]), text(&case["tag"]));
        check(&mut differences, "image validate", case, &case["validate"], &json!(reference.validate()));
        if !case["format"].is_null() {
            check(&mut differences, "image format", case, &case["format"], &json!(reference.format()));
        }
        check(&mut differences, "image display", case, &case["displayName"], &json!(reference.display_name()));
        checked += 1;
    }

    for case in rules["assetTier"].as_array().unwrap() {
        let input = text(&case["input"]);
        let from_input = AssetTier::from_input(input).map(|tier| tier.name());
        check(&mut differences, "tier from input", case, &case["fromInput"], &outcome(from_input));
        check(
            &mut differences,
            "tier from string",
            case,
            &case["fromString"],
            &json!(AssetTier::from_string(input).name()),
        );
        checked += 1;
    }

    for case in rules["requiredLabel"].as_array().unwrap() {
        let got = agent_labels::normalize_requirement(text(&case["input"]));
        check(&mut differences, "label", case, &case["normalizeRequirement"], &json!(got));
        checked += 1;
    }

    let rows: Vec<i64> = (0..12).collect();
    for case in rules["listWindow"].as_array().unwrap() {
        let got = match ListWindow::requested(case["limit"].as_i64(), case["offset"].as_i64()) {
            Ok(None) => json!({ "page": null }),
            Ok(Some(window)) => json!({ "page": window.of(&rows) }),
            Err(refused) => json!({ "refused": refused }),
        };
        let expected = match case.get("refused") {
            Some(refused) => json!({ "refused": refused }),
            None => json!({ "page": case["page"] }),
        };
        check(&mut differences, "list window", case, &expected, &got);
        checked += 1;
    }

    for case in rules["gitHostAllowlist"].as_array().unwrap() {
        let got = match GitHostAllowlist::parse(text(&case["configured"])) {
            Err(refused) => json!({ "configured": case["configured"], "refused": refused.0 }),
            Ok(list) => {
                let checks: Vec<Value> = case["checks"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|check| {
                        let url = check["url"].as_str().unwrap();
                        json!({ "url": url, "permits": list.permits(url), "refusal": list.refusal(url) })
                    })
                    .collect();
                json!({ "configured": case["configured"], "entries": list.entries, "checks": checks })
            }
        };
        check(&mut differences, "allow-list", &case["configured"], case, &got);
        checked += 1;
    }

    for case in rules["inForce"].as_array().unwrap() {
        let stored = crontab::parse(text(&case["cron"]));
        let interval = case["intervalMinutes"].as_i64().map(|minutes| i32::try_from(minutes).unwrap());
        let in_force = schedules::in_force(
            case["manualOnly"].as_bool().unwrap(),
            &stored,
            interval,
            case["defaultDays"].as_i64().unwrap() * 24 * 60,
        );
        check(&mut differences, "in force mode", case, &case["mode"], &json!(in_force.mode.wire_name()));
        check(&mut differences, "in force minutes", case, &case["minutes"], &json!(in_force.interval_minutes));
        checked += 1;
    }

    for case in rules["caseInsensitiveOrder"].as_array().unwrap() {
        let order = java::compare_ignore_case(case["left"].as_str().unwrap(), case["right"].as_str().unwrap());
        let sign = match order {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        };
        check(&mut differences, "case-insensitive order", case, &case["sign"], &json!(sign));
        checked += 1;
    }

    assert!(differences.is_empty(), "{} of {checked} cases differ:\n{}", differences.len(), differences.join("\n"));
    println!("{checked} cases agree with Java");
}
