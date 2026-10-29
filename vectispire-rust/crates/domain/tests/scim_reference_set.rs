//! SCIM's pure rules against `reference/access/scim/java-answers.json`, which `ScimReferenceSetTest` (in
//! `vectispire-core`) writes from `ScimProvisioningService` itself, its repositories mocked and recording what they were
//! asked: the users' filters — the lookup made, or the controller's 400 with its `scimType` and `detail` — the pages,
//! the member a PATCH entry names and the one a `remove` path takes away. Every difference is collected and reported
//! at once.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use serde_json::{Value, json};
use vectispire_domain::scim::{self, MemberRef, Page, Removal, UserFilter};

fn answers() -> Value {
    vectispire_testkit::read_json("access/scim/java-answers.json")
}

fn cases<'a>(answers: &'a Value, section: &str, at_least: usize) -> &'a Vec<Value> {
    let cases = answers[section].as_array().unwrap();
    assert!(cases.len() >= at_least, "{section}: the reference set is thinner than it was written");
    cases
}

fn report(differences: &[String]) {
    assert!(differences.is_empty(), "{} differences:\n{}", differences.len(), differences.join("\n"));
}

/// The lookup the Java mock records for a member reference.
fn lookup(reference: &MemberRef) -> String {
    match reference {
        MemberRef::Id(id) => format!("id {id}"),
        MemberRef::UserName(name) => format!("userName {name}"),
    }
}

#[test]
fn filters_are_read_and_refused_as_java_reads_them() {
    let answers = answers();
    let mut differences = Vec::new();
    for case in cases(&answers, "filters", 80) {
        let input = case["input"].as_str();
        let got = match scim::user_filter(input) {
            Ok(None) => json!({ "lookups": ["all"] }),
            Ok(Some(UserFilter::UserName(name))) => json!({ "lookups": [format!("userName {name}")] }),
            Ok(Some(UserFilter::ExternalId(subject))) => json!({ "lookups": [format!("externalId {subject}")] }),
            Err(refused) => json!({
                "httpStatus": 400,
                "status": "400",
                "scimType": scim::INVALID_FILTER,
                "detail": refused.0,
            }),
        };
        let mut expected = case.clone();
        expected.as_object_mut().unwrap().remove("input");
        if got != expected {
            differences.push(format!("{input:?}: Java {expected}, Rust {got}"));
        }
    }
    report(&differences);
}

#[test]
fn pages_are_cut_as_java_cuts_them() {
    let answers = answers();
    let mut differences = Vec::new();
    for case in cases(&answers, "pages", 30) {
        let input = &case["input"];
        let size = usize::try_from(input["size"].as_u64().unwrap()).unwrap();
        let int = |field: &str| input[field].as_i64().map(|value| i32::try_from(value).unwrap());
        let page = Page::of((0..size).collect::<Vec<_>>(), int("startIndex"), int("count"));
        let got = json!({
            "input": input,
            "first": page.resources.first(),
            "size": page.resources.len(),
            "totalResults": page.total_results,
            "startIndex": page.start_index,
        });
        if &got != case {
            differences.push(format!("{input}: Java {case}, Rust {got}"));
        }
    }
    report(&differences);
}

#[test]
fn page_map_keeps_the_count_and_the_start() {
    let page = Page::of(vec![1, 2, 3], Some(2), Some(1)).map(|n| n * 10);
    assert_eq!(page, Page { resources: vec![20], total_results: 3, start_index: 2 });
}

#[test]
fn a_patch_entry_names_the_member_java_names() {
    let answers = answers();
    let mut differences = Vec::new();
    for case in cases(&answers, "memberItems", 50) {
        let item = &case["input"];
        // `item.has("value")`, then `resolveUserId(item.get("value").asString(null))`.
        let got: Vec<String> = item
            .as_object()
            .and_then(|entry| entry.get("value"))
            .and_then(scim::member_value_text)
            .and_then(|text| scim::member_ref(Some(&text)))
            .map(|reference| lookup(&reference))
            .into_iter()
            .collect();
        let expected: Vec<String> = serde_json::from_value(case["lookups"].clone()).unwrap();
        if got != expected {
            differences.push(format!("{item}: Java {expected:?}, Rust {got:?}"));
        }
    }
    report(&differences);
}

#[test]
fn a_removal_path_takes_away_the_member_java_takes_away() {
    let answers = answers();
    let mut differences = Vec::new();
    for case in cases(&answers, "removalPaths", 30) {
        let input = case["input"].as_str();
        // The Java mocks find every identifier and every name, so a reference is always removed.
        let got: Vec<String> = match scim::removal(input) {
            Removal::One(value) => scim::member_ref(Some(&value))
                .map(|reference| vec![lookup(&reference), "remove one".to_owned()])
                .unwrap_or_default(),
            Removal::Everyone => vec!["remove everyone".to_owned()],
            Removal::Nothing => Vec::new(),
        };
        let expected: Vec<String> = serde_json::from_value(case["lookups"].clone()).unwrap();
        if got != expected {
            differences.push(format!("{input:?}: Java {expected:?}, Rust {got:?}"));
        }
    }
    report(&differences);
}
