//! Argon2id against what the Java side writes and reads (`vectispire-rust/reference/accounts/`).
//!
//! - `java-hashes.json`: hashes `PasswordHasher` made; each must verify here, refuse a neighbour, and say whether it
//!   needs a rehash as Java says.
//! - `rust-hashes.json`: hashes this crate made, which `AccountsReferenceSetTest` verifies on the Java side.
//!   `VECTISPIRE_RUST_REFERENCE_WRITE=1` regenerates it; otherwise each entry must still verify here.
//! - `verify.json`: `verify` over malformed and odd encodings. Where Java *throws* — BouncyCastle refusing the
//!   parameters — the Rust answer is `false`, the documented difference (`passwords.rs`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use serde_json::{Value, json};
use vectispire_cp_access::passwords::{self, HashError, ITERATIONS, MEMORY_KIB, PARALLELISM};

fn reference(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference/accounts").join(name)
}

fn read(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(reference(name)).unwrap_or_else(|error| panic!("{name}: {error}")))
        .unwrap()
}

/// The same invented passphrases the Java side hashes.
const CANDIDATES: &[&str] = &[
    "an invented passphrase",
    "Invented-Passphrase-2026!",
    "",
    " leading and trailing ",
    "accentué et café crème",
    "日本語のパスフレーズです",
    "emoji 🙂🙂🙂🙂🙂🙂 inside",
    "tab\tand\nnewline inside it",
];

#[test]
fn every_java_hash_verifies_here_and_says_what_java_says() {
    let entries = read("java-hashes.json");
    let entries = entries.as_array().unwrap();
    assert!(entries.len() >= 9, "the Java side wrote {} hashes", entries.len());
    for entry in entries {
        let candidate = entry["candidate"].as_str().unwrap();
        let phc = entry["phc"].as_str().unwrap();
        assert_eq!(passwords::verify(Some(candidate), Some(phc)), entry["verifies"].as_bool().unwrap(), "{phc}");
        let other = format!("{candidate}?");
        assert_eq!(passwords::verify(Some(&other), Some(phc)), entry["verifiesOther"].as_bool().unwrap(), "{phc}");
        assert_eq!(passwords::needs_rehash(Some(phc)), entry["needsRehash"].as_bool().unwrap(), "{phc}");
    }
}

#[test]
fn rust_hashes_are_written_for_the_java_side_and_still_verify_here() {
    let file = reference("rust-hashes.json");
    if std::env::var("VECTISPIRE_RUST_REFERENCE_WRITE").as_deref() == Ok("1") {
        let mut entries = Vec::new();
        for candidate in CANDIDATES {
            let phc = passwords::hash(candidate);
            entries
                .push(json!({"candidate": candidate, "phc": phc, "needsRehash": passwords::needs_rehash(Some(&phc))}));
        }
        let weaker = passwords::hash_with(CANDIDATES[0], 4096, 1, 1).unwrap();
        entries.push(json!({"candidate": CANDIDATES[0], "phc": weaker, "needsRehash": true}));
        let lanes = passwords::hash_with(CANDIDATES[1], MEMORY_KIB, ITERATIONS, 4).unwrap();
        entries.push(json!({"candidate": CANDIDATES[1], "phc": lanes, "needsRehash": false}));
        std::fs::write(&file, serde_json::to_string_pretty(&Value::Array(entries)).unwrap() + "\n").unwrap();
    }
    let entries = read("rust-hashes.json");
    let entries = entries.as_array().unwrap();
    assert!(entries.len() >= CANDIDATES.len());
    for entry in entries {
        let candidate = entry["candidate"].as_str().unwrap();
        let phc = entry["phc"].as_str().unwrap();
        assert!(passwords::verify(Some(candidate), Some(phc)), "{phc}");
        assert_eq!(passwords::needs_rehash(Some(phc)), entry["needsRehash"].as_bool().unwrap());
    }
}

#[test]
fn verify_on_the_edges_answers_what_java_answers() {
    let entries = read("verify.json");
    let entries = entries.as_array().unwrap();
    assert!(entries.len() >= 30);
    let mut throws = 0;
    for entry in entries {
        let case = entry["case"].as_str().unwrap();
        let candidate = entry["candidate"].as_str();
        let phc = entry["phc"].as_str();
        let java = entry["verify"].as_str().unwrap();
        let expected = match java {
            "true" => true,
            "false" => false,
            thrown if thrown.starts_with("throws ") => {
                throws += 1;
                false
            }
            other => panic!("{case}: unexpected outcome {other}"),
        };
        assert_eq!(passwords::verify(candidate, phc), expected, "{case}: Java {java}");
        assert_eq!(passwords::needs_rehash(phc), entry["needsRehash"].as_bool().unwrap(), "{case}: needsRehash");
    }
    // Pinned so that a change on either side is seen: today BouncyCastle throws for these parameter sets.
    assert_eq!(throws, 2, "BouncyCastle throws for t=0 and p=0 today");
}

#[test]
fn todays_parameters_are_the_javadocs() {
    assert_eq!((MEMORY_KIB, ITERATIONS, PARALLELISM), (19_456, 2, 1));
    let phc = passwords::hash("an invented passphrase");
    let parts: Vec<&str> = phc.split('$').collect();
    assert_eq!(&parts[..4], ["", "argon2id", "v=19", "m=19456,t=2,p=1"]);
    // 16 bytes and 32 bytes, standard base64 without padding.
    assert_eq!(parts[4].len(), 22);
    assert_eq!(parts[5].len(), 43);
    assert!(!parts[4].contains('=') && !parts[5].contains('='));
    assert!(passwords::verify(Some("an invented passphrase"), Some(&phc)));
    assert!(!passwords::needs_rehash(Some(&phc)));
}

#[test]
fn two_hashes_of_one_password_differ_by_their_salt() {
    assert_ne!(passwords::hash("an invented passphrase"), passwords::hash("an invented passphrase"));
}

#[test]
fn parameters_argon2_refuses_are_an_error_not_a_hash() {
    assert_eq!(
        passwords::hash_with("x", 4, 2, 1),
        Err(HashError::Parameters { memory_kib: 4, iterations: 2, parallelism: 1 })
    );
}

#[test]
fn a_memory_cost_past_the_ceiling_is_refused_without_being_allocated() {
    let phc = passwords::hash("an invented passphrase");
    let parts: Vec<&str> = phc.split('$').collect();
    // Two tebibytes: without the ceiling the derivation would try to allocate them, and the process would end.
    let huge = format!("$argon2id$v=19$m={},t=2,p=1${}${}", i32::MAX, parts[4], parts[5]);
    assert!(!passwords::verify(Some("an invented passphrase"), Some(&huge)));
}

#[test]
fn the_stand_in_is_a_well_formed_hash_of_nothing_typed() {
    let stand_in = passwords::hash_of_nothing_anybody_knows();
    assert!(!passwords::needs_rehash(Some(&stand_in)));
    assert!(!passwords::verify(Some(""), Some(&stand_in)));
}
