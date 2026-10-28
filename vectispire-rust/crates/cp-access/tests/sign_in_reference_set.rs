//! The second factor and the sign-in throttle held to what the Java side answers — `reference/sign-in/`, written by
//! `SignInReferenceSetTest` in `vectispire-common`.
//!
//! A TOTP secret decoded differently, a step counted differently around the epoch or a code trimmed differently is an
//! authenticator that stops working on the day the control plane changes language; a throttle key folded differently
//! is a fresh budget for every spelling. Every difference is collected and reported at once.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use vectispire_cp_access::login_throttle::{self, Decision};
use vectispire_cp_access::totp;
use vectispire_cp_http::address::client_bucket;

fn answers() -> Value {
    vectispire_testkit::read_json("sign-in/java-answers.json")
}

fn instant(value: &Value) -> OffsetDateTime {
    OffsetDateTime::parse(value.as_str().unwrap(), &Rfc3339).unwrap()
}

fn instants(value: &Value) -> Vec<OffsetDateTime> {
    value.as_array().unwrap().iter().map(instant).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap()).collect()
}

/// The section, refusing one thinner than it was written: a reference set that lost its cases checks nothing.
fn section<'a>(answers: &'a Value, name: &str, at_least: usize) -> &'a Vec<Value> {
    let cases = answers[name].as_array().unwrap();
    assert!(cases.len() >= at_least, "{name}: {} cases, at least {at_least} written", cases.len());
    cases
}

fn report(differences: &[String]) {
    assert!(differences.is_empty(), "{} differences:\n{}", differences.len(), differences.join("\n"));
}

#[test]
fn base32_reads_and_writes_as_java_does() {
    let answers = answers();
    let mut differences = Vec::new();
    for case in section(&answers, "base32Encode", 10) {
        let got = totp::encode_base32(&unhex(case["hex"].as_str().unwrap()));
        if got != case["base32"].as_str().unwrap() {
            differences.push(format!("encode {}: Java {}, Rust {got}", case["hex"], case["base32"]));
        }
    }
    for case in section(&answers, "base32Decode", 20) {
        let got = hex(&totp::decode_base32(case["base32"].as_str().unwrap()));
        if got != case["hex"].as_str().unwrap() {
            differences.push(format!("decode {}: Java {}, Rust {got}", case["base32"], case["hex"]));
        }
    }
    report(&differences);
}

/// RFC 6238's own vectors among them (the secret `12345678901234567890`), and the steps either side of the epoch.
#[test]
fn a_code_is_the_one_java_computes() {
    let answers = answers();
    let mut differences = Vec::new();
    for case in section(&answers, "codes", 15) {
        let got = totp::generate_code(case["seed"].as_str().unwrap(), instant(&case["instant"]));
        if got.as_deref() != case["code"].as_str() {
            differences.push(format!("{} at {}: Java {}, Rust {got:?}", case["seed"], case["instant"], case["code"]));
        }
    }
    report(&differences);
}

#[test]
fn a_submitted_code_matches_the_step_java_matches() {
    let answers = answers();
    let mut differences = Vec::new();
    for case in section(&answers, "matches", 25) {
        let got = totp::matching_step(case["seed"].as_str(), case["code"].as_str(), instant(&case["instant"]));
        if got != case["step"].as_i64() {
            differences.push(format!(
                "{} / {} at {}: Java {}, Rust {got:?}",
                case["seed"], case["code"], case["instant"], case["step"]
            ));
        }
    }
    report(&differences);
}

#[test]
fn the_enrolment_uri_is_encoded_as_java_encodes_it() {
    let answers = answers();
    let mut differences = Vec::new();
    for case in section(&answers, "uris", 7) {
        let got =
            totp::qr_code_uri(case["username"].as_str().unwrap(), "JBSWY3DPEHPK3PXP", case["issuer"].as_str().unwrap());
        if got != case["uri"].as_str().unwrap() {
            differences.push(format!("Java {}, Rust {got}", case["uri"]));
        }
    }
    report(&differences);
}

/// The fold that keeps a typed name from being several budgets: compatibility decomposition, marks, the root
/// locale's case mappings with Java's final sigma, and the letters MySQL's collation equates.
#[test]
fn a_typed_name_is_counted_under_javas_key() {
    let answers = answers();
    let mut differences = Vec::new();
    for case in section(&answers, "userKeys", 50) {
        let got = login_throttle::user_key(case["username"].as_str().unwrap());
        if got != case["key"].as_str().unwrap() {
            differences.push(format!("{}: Java {}, Rust {got}", case["username"], case["key"]));
        }
    }
    assert_eq!(login_throttle::account_key(42), answers["accountKey"].as_str().unwrap());
    assert_eq!(login_throttle::second_factor_key(42), answers["secondFactorKey"].as_str().unwrap());
    report(&differences);
}

/// `ClientBuckets.of` and the client key: `InetAddress.ofLiteral`'s grammar — shortened and zero-padded IPv4, at most
/// fifteen characters of it, numeric scope ids, IPv4 inside IPv6 — decides which addresses share a budget.
#[test]
fn an_address_spends_the_budget_java_spends() {
    let answers = answers();
    let mut differences = Vec::new();
    for case in section(&answers, "addresses", 90) {
        // `String.valueOf(null)`: the text Java's callers hand over for an absent address.
        let address = case["address"].as_str().unwrap_or("null");
        let bucket = client_bucket(address);
        if bucket != case["bucket"].as_str().unwrap() {
            differences.push(format!("bucket {}: Java {}, Rust {bucket:?}", case["address"], case["bucket"]));
        }
        let key = login_throttle::client_key(address);
        if key != case["clientKey"].as_str().unwrap() {
            differences.push(format!("key {}: Java {}, Rust {key:?}", case["address"], case["clientKey"]));
        }
    }
    report(&differences);
}

fn decided(case: &Value, decision: Decision) -> Option<String> {
    let expected = Decision {
        allowed: case["allowed"].as_bool().unwrap(),
        retry_after: Duration::new(
            case["retryAfterSeconds"].as_i64().unwrap(),
            i32::try_from(case["retryAfterNanos"].as_i64().unwrap()).unwrap(),
        ),
    };
    (decision != expected).then(|| format!("{}: Java {expected:?}, Rust {decision:?}", case["name"]))
}

/// The window's edges to the nanosecond: a failure exactly at the cutoff has left, one a nanosecond inside still
/// counts, and the wait is never announced under a second.
#[test]
fn the_throttle_decides_as_java_decides() {
    let inputs = vectispire_testkit::read_json("sign-in/inputs.json");
    let answers = answers();
    let mut differences = Vec::new();
    let both = section(&answers, "throttle", 15);
    for (input, case) in inputs["throttle"].as_array().unwrap().iter().zip(both) {
        assert_eq!(input["name"], case["name"]);
        let decision =
            login_throttle::decide(&instants(&input["user"]), &instants(&input["client"]), instant(&input["now"]));
        differences.extend(decided(case, decision));
    }
    let one = section(&answers, "throttleOne", 4);
    for (input, case) in inputs["throttleOne"].as_array().unwrap().iter().zip(one) {
        assert_eq!(input["name"], case["name"]);
        let limit = usize::try_from(input["limit"].as_u64().unwrap()).unwrap();
        let decision = login_throttle::decide_one(&instants(&input["attempts"]), limit, instant(&input["now"]));
        differences.extend(decided(case, decision));
    }
    report(&differences);
}
