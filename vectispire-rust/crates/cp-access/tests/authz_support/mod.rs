//! Reading `reference/access/`, the Java side's answers (`AccessReferenceSetTest`).

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::Value;
use vectispire_cp_access::visibility::{Allowance, Grant};
use vectispire_cp_db::{ScanTarget, Visibility};

pub fn reference(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference/access").join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("{} is read", path.display()));
    serde_json::from_str(&text).unwrap()
}

pub fn target(value: &Value) -> ScanTarget {
    if let Some(id) = value.get("repository") {
        ScanTarget::Repository(id.as_i64().unwrap())
    } else {
        ScanTarget::Container(value["container"].as_i64().unwrap())
    }
}

pub fn targets(value: &Value) -> Vec<ScanTarget> {
    value.as_array().unwrap().iter().map(target).collect()
}

pub fn visibility(value: &Value) -> Visibility {
    if value.as_str() == Some("everything") {
        Visibility::everything()
    } else {
        Visibility::only(targets(&value["only"]))
    }
}

pub fn allowance(value: &Value) -> Allowance {
    Allowance {
        visibility: visibility(&value["visibility"]),
        granted_projects: value["grantedProjects"].as_array().unwrap().iter().map(|id| id.as_i64().unwrap()).collect(),
        narrowed_by_credential: value["narrowedByCredential"].as_bool().unwrap(),
    }
}

pub fn grants(value: &Value) -> Vec<Grant> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| Grant { kind: pair[0].as_str().unwrap().to_owned(), id: pair[1].as_i64().unwrap() })
        .collect()
}

/// A setup's grants as the account receives them: its own, then each team's.
pub fn grants_of_setup(setup: &Value) -> Vec<Grant> {
    let mut all = grants(&setup["direct"]);
    for team in setup["teams"].as_array().unwrap() {
        all.extend(grants(&team["grants"]));
    }
    all
}

/// What `GrantableTargets.targetsIn` answered in the Java run, from the fixture's projects.
pub fn filed_in(projects: &Value, wanted: &BTreeSet<i64>) -> Vec<ScanTarget> {
    let mut filed = Vec::new();
    for id in wanted {
        if let Some(targets_of) = projects.get(id.to_string()) {
            filed.extend(targets(targets_of));
        }
    }
    filed
}
