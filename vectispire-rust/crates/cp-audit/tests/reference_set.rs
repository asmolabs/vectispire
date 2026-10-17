//! The chain held to what the Java side answers (`reference/audit/`, written by `AuditChainReferenceSetTest`):
//! the canonical instant and the hash of every field shape, the verdict of every verification case, the
//! rebuilt chains, and the operations' wire names.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use vectispire_cp_audit::AuditOperation;
use vectispire_cp_audit::chain::{self, Entry, VerifiableEntry};
use vectispire_testkit::read_json;

fn text(value: &Value) -> Option<String> {
    value.as_str().map(str::to_owned)
}

fn entry(value: &Value) -> Entry {
    Entry {
        previous_hash: text(&value["previousHash"]),
        timestamp: value["timestamp"].as_str().map(|at| OffsetDateTime::parse(at, &Rfc3339).unwrap()),
        operation_type: text(&value["operationType"]),
        resource_id: text(&value["resourceId"]),
        user_id: text(&value["userId"]),
        ip_address: text(&value["ipAddress"]),
        user_agent: text(&value["userAgent"]),
        description: text(&value["description"]),
    }
}

fn entries(value: &Value) -> Vec<VerifiableEntry> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|node| VerifiableEntry {
            id: node["id"].as_str().unwrap().to_owned(),
            entry_hash: text(&node["entryHash"]),
            entry: entry(&node["entry"]),
        })
        .collect()
}

#[test]
fn every_entry_hashes_to_the_bytes_java_computes() {
    let set = read_json("audit/chain.json");
    let cases = set["hashes"].as_array().unwrap();
    assert!(cases.len() >= 15, "the set has its cases");
    for case in cases {
        let entry = entry(&case["entry"]);
        assert_eq!(
            entry.timestamp.map(chain::canonical),
            text(&case["canonical"]),
            "canonical of {:?}",
            entry.timestamp
        );
        assert_eq!(chain::entry_hash(&entry), case["hash"].as_str().unwrap(), "hash of {entry:?}");
    }
}

#[test]
fn every_verification_reaches_java_s_verdict_in_java_s_words() {
    let set = read_json("audit/chain.json");
    for case in set["verifications"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let verification = chain::verify(&entries(&case["entries"]));
        assert_eq!(verification.broken, text(&case["broken"]), "{name}");
        assert_eq!(verification.unverifiable as u64, case["unverifiable"].as_u64().unwrap(), "{name}");
    }
}

#[test]
fn every_rebuild_relinks_as_java_does() {
    let set = read_json("audit/chain.json");
    for case in set["rebuilds"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        assert_eq!(chain::rebuild(&entries(&case["entries"])), entries(&case["rebuilt"]), "{name}");
    }
}

#[test]
fn the_operations_are_java_s_in_java_s_order() {
    let java: Vec<(String, String)> = vectispire_testkit::read("audit/operations.txt")
        .lines()
        .map(|line| {
            let (name, wire) = line.split_once('\t').unwrap();
            (name.to_owned(), wire.to_owned())
        })
        .collect();
    let rust: Vec<(String, String)> = AuditOperation::ALL
        .iter()
        .map(|operation| (operation.wire_name().to_owned(), operation.wire_name().to_owned()))
        .collect();
    assert_eq!(rust, java);
    for operation in AuditOperation::ALL {
        assert_eq!(AuditOperation::from_wire(operation.wire_name()), Some(operation));
    }
    assert_eq!(AuditOperation::from_wire("NO_SUCH_OPERATION"), None, "an old row's operation is read as text");
}
