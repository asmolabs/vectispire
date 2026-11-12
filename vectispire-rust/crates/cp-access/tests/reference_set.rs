//! The credential rules held to what the Java side answers — `reference/credentials/`, written by
//! `CredentialsReferenceSetTest` in `vectispire-common`.
//!
//! A session's hash, the header a session is read from, a session's state, an API key's scopes and the Argon2id PHC
//! strings: each is what decides whether a user signed in on the Java control plane is still signed in on the Rust
//! one, and whether a pipeline's key still works. A difference here is a failing test, not a style question.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use serde_json::Value;
use std::path::PathBuf;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use vectispire_cp_access::credentials::{
    SessionPolicy, SessionState, bearer_token, handoff_hash_of, hash_of, normalize_lifetime, normalize_scopes, phc,
    scope_from_wire_name, should_record_activity, state_of,
};

fn reference(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference/credentials").join(name);
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))).unwrap()
}

fn instant(value: &Value) -> OffsetDateTime {
    OffsetDateTime::parse(value.as_str().unwrap(), &Rfc3339).unwrap()
}

/// `java.time.Duration.parse` for the forms the inputs use: `PT12H`, `PT60M`, `PT30S`, `PT1H41M40.000000001S`.
fn duration(value: &Value) -> Duration {
    let text = value.as_str().unwrap().strip_prefix("PT").unwrap();
    let mut total = Duration::ZERO;
    let mut number = String::new();
    for c in text.chars() {
        match c {
            'H' => total += Duration::hours(number.parse().unwrap()),
            'M' => total += Duration::minutes(number.parse().unwrap()),
            'S' => {
                let (whole, fraction) = number.split_once('.').unwrap_or((&number, ""));
                let nanos: i64 = format!("{fraction:0<9}").parse().unwrap();
                total += Duration::seconds(whole.parse().unwrap()) + Duration::nanoseconds(nanos);
            }
            _ => {
                number.push(c);
                continue;
            }
        }
        number.clear();
    }
    total
}

#[test]
fn a_token_is_hashed_as_java_hashes_it() {
    let answers = reference("java-answers.json");
    let entries = answers["tokenHashes"].as_array().unwrap();
    assert!(entries.len() >= 10);
    for entry in entries {
        let token = entry["token"].as_str().unwrap();
        assert_eq!(hash_of(token), entry["hash"].as_str().unwrap(), "{token:?}");
        assert_eq!(handoff_hash_of(token), entry["handoffHash"].as_str().unwrap(), "{token:?}");
    }
}

#[test]
fn a_session_header_is_read_as_java_reads_it() {
    let answers = reference("java-answers.json");
    let entries = answers["bearer"].as_array().unwrap();
    assert!(entries.len() >= 20);
    for entry in entries {
        let header = entry["header"].as_str();
        assert_eq!(bearer_token(header), entry["token"].as_str(), "{header:?}");
    }
}

#[test]
fn a_session_closes_and_records_its_activity_as_java_decides() {
    let inputs = reference("inputs.json");
    let answers = reference("java-answers.json");
    let states = inputs["states"].as_array().unwrap();
    assert_eq!(states.len(), answers["states"].as_array().unwrap().len());
    for (input, answer) in states.iter().zip(answers["states"].as_array().unwrap()) {
        let policy =
            SessionPolicy { absolute_lifetime: duration(&input["absolute"]), idle_lifetime: duration(&input["idle"]) };
        let (created, last_seen, now) =
            (instant(&input["createdAt"]), instant(&input["lastSeenAt"]), instant(&input["now"]));
        let state = match state_of(created, last_seen, now, &policy) {
            SessionState::Active => "ACTIVE",
            SessionState::Expired => "EXPIRED",
            SessionState::Idle => "IDLE",
        };
        assert_eq!(state, answer["state"].as_str().unwrap(), "{}", answer["name"]);
        assert_eq!(
            should_record_activity(last_seen, now, &policy),
            answer["recordActivity"].as_bool().unwrap(),
            "{}",
            answer["name"]
        );
    }
}

#[test]
fn scopes_and_lifetimes_are_normalised_with_the_java_answers_and_sentences() {
    let answers = reference("java-answers.json");
    for entry in answers["scopeLists"].as_array().unwrap() {
        let requested: Option<Vec<Option<String>>> =
            entry["input"].as_array().map(|list| list.iter().map(|scope| scope.as_str().map(str::to_owned)).collect());
        match normalize_scopes(requested.as_deref()) {
            Ok(scopes) => {
                let names: Vec<&str> = scopes.iter().map(|scope| scope.wire_name()).collect();
                let expected: Vec<&str> =
                    entry["scopes"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
                assert_eq!(names, expected, "{}", entry["input"]);
            }
            Err(refusal) => assert_eq!(refusal.to_string(), entry["error"].as_str().unwrap(), "{}", entry["input"]),
        }
    }
    for entry in answers["lifetimes"].as_array().unwrap() {
        let days = entry["input"].as_i64().map(|days| i32::try_from(days).unwrap());
        match normalize_lifetime(days) {
            Ok(days) => assert_eq!(days.map(i64::from), entry["days"].as_i64(), "{}", entry["input"]),
            Err(refusal) => assert_eq!(refusal.to_string(), entry["error"].as_str().unwrap(), "{}", entry["input"]),
        }
    }
    for entry in answers["wireNames"].as_array().unwrap() {
        let input = entry["input"].as_str().unwrap();
        assert_eq!(scope_from_wire_name(input).map(|scope| scope.wire_name()), entry["scope"].as_str(), "{input:?}");
    }
}

#[test]
fn a_phc_string_java_wrote_verifies_here_exactly_where_it_verifies_there() {
    let inputs = reference("inputs.json");
    let minted = reference("java-minted.json");
    let answers = reference("java-answers.json");
    let secrets: Vec<&str> = inputs["secrets"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
    let encoded: std::collections::HashMap<&str, Option<&str>> = minted["encoded"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| (entry["name"].as_str().unwrap(), entry["value"].as_str()))
        .collect();
    let verdicts = answers["verify"].as_array().unwrap();
    assert!(verdicts.len() >= 200, "{} verdicts", verdicts.len());
    let mut matched = 0;
    for verdict in verdicts {
        let name = verdict["encoded"].as_str().unwrap();
        let value = encoded[name];
        let secret = secrets[usize::try_from(verdict["secret"].as_u64().unwrap()).unwrap()];
        let expected = verdict["matches"].as_bool().unwrap();
        assert_eq!(value.is_some_and(|value| phc::verify(secret, value)), expected, "{name} against secret {secret:?}");
        matched += usize::from(expected);
    }
    assert!(matched >= 30, "the set proves acceptance too, not only refusals ({matched})");
    for entry in answers["needsRehash"].as_array().unwrap() {
        let name = entry["encoded"].as_str().unwrap();
        assert_eq!(phc::needs_rehash(encoded[name]), entry["needs"].as_bool().unwrap(), "{name}");
    }
}
