//! The audit log's vocabulary against the SIEM's (`vectispire_domain::siem`), which the domain crate cannot check
//! itself since it cannot see this one.
//!
//! - Java's `SecurityEventType.signalledBy` is a switch over every `AuditOperation`, without a default: an
//!   operation added to the enum does not compile until somebody decides whether it signals. Here the operations
//!   are this crate's and the placement the domain's, so the same decision is forced by a test.
//! - A [`Signal`] carries a `SecurityEventType` by its wire name. A name no event has would be carried to the export
//!   and dropped there, or worse, read as nothing: every signal written in the workspace with a literal name is
//!   held to the catalogue.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use vectispire_cp_audit::AuditOperation;
use vectispire_domain::siem::SecurityEventType;
use vectispire_domain::siem::event_type::{self, QUIET, SIGNALLING};

#[test]
fn every_operation_is_placed_on_one_side_or_the_other() {
    let unplaced: Vec<&str> = AuditOperation::ALL
        .iter()
        .map(|operation| operation.wire_name())
        .filter(|name| event_type::placement(name).is_none())
        .collect();
    assert!(unplaced.is_empty(), "place these in siem::event_type, signalling or quiet: {unplaced:?}");
}

#[test]
fn every_placed_name_is_an_operation() {
    let names = SIGNALLING.iter().map(|(name, _)| *name).chain(QUIET.iter().copied());
    let strays: Vec<&str> = names.filter(|name| AuditOperation::from_wire(name).is_none()).collect();
    assert!(strays.is_empty(), "no audit operation has these names: {strays:?}");
    assert_eq!(SIGNALLING.len() + QUIET.len(), AuditOperation::ALL.len());
}

/// Every signal with a literal name in the workspace's sources, tests included: a test that signals a name no
/// event has would pin a behaviour the export cannot have.
#[test]
fn every_signal_written_in_the_workspace_names_an_event() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut sources = Vec::new();
    collect_rust_sources(&crates, &mut sources);
    let pattern = regex::Regex::new(r#"\bSignal\("([^"]*)"\)"#).unwrap();
    let mut found = Vec::new();
    let mut unknown = Vec::new();
    for source in sources {
        let text = std::fs::read_to_string(&source).unwrap();
        for capture in pattern.captures_iter(&text) {
            let name = capture[1].to_owned();
            if SecurityEventType::from_wire_name(&name).is_none() {
                unknown.push(format!("{}: {name}", source.display()));
            }
            found.push(name);
        }
    }
    assert!(unknown.is_empty(), "signals naming no SecurityEventType: {unknown:?}");
    // The three the port writes today; a scan that found none would have checked nothing.
    for expected in ["BEARER_TOKEN_THROTTLED", "SECURITY_SETTING_CHANGED", "ACCESS_GRANT_CHANGED"] {
        assert!(found.iter().any(|name| name == expected), "{expected} was not found: the scan read the wrong files");
    }
}

fn collect_rust_sources(dir: &Path, into: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            collect_rust_sources(&path, into);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            into.push(path);
        }
    }
}
