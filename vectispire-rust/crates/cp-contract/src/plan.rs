//! What a replay of the Java suite's recorded traffic has to do, before there is anything to replay it against.
//!
//! The recorder (`vectispire-java/…/core/golden/`) writes one file per request of every HTTP test. The Rust control
//! plane serves none of those routes yet, so replaying them all would fail on the first and say nothing. What can
//! be held from the first day is the **plan**: every recording is read (a format that drifted between the recorder
//! and this reader is a failure now, not on the day the first route is ported), every recorded request is matched
//! to an operation of the contract, and each is sorted — **not yet ported** (its route is on the contract's list
//! that only shrinks: nothing to replay), **to replay** (its route has left the list: the day a route is ported,
//! its recordings are owed a replay), or **outside the contract** (a request no operation answers: the interface's
//! own files, the actuator, an unknown path). A route that is ported while its recordings are not replayed is
//! the one thing this refuses: the list shrinking is how the replay is turned on.

use std::collections::BTreeSet;

use crate::document::Document;
use crate::golden::Golden;
use crate::routes::Allowlist;

/// How the recordings sort.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Every recording read.
    pub total: usize,
    /// Recorded requests whose route is still on the list of routes not yet ported.
    pub not_ported: usize,
    /// The recordings of a route that has been ported: `name (METHOD template)`, owed a replay.
    pub to_replay: Vec<String>,
    /// Recorded requests no operation of the contract answers: `METHOD path`, each once.
    pub outside_contract: BTreeSet<String>,
    /// Operations of the contract that have at least one recording.
    pub operations_recorded: usize,
}

impl Plan {
    /// Whether nothing is owed: no ported route has a recording waiting to be replayed.
    #[must_use]
    pub fn owes_nothing(&self) -> bool {
        self.to_replay.is_empty()
    }
}

/// Sorts `goldens` against the contract and the list of routes not yet ported.
#[must_use]
pub fn plan(goldens: &[Golden], document: &Document, not_ported: &Allowlist) -> Plan {
    let mut plan = Plan { total: goldens.len(), ..Plan::default() };
    let mut recorded: BTreeSet<(String, String)> = BTreeSet::new();
    for golden in goldens {
        let method = golden.request.method.to_ascii_uppercase();
        match document.find(&method, &golden.request.path) {
            None => {
                plan.outside_contract.insert(format!("{method} {}", golden.request.path));
            }
            Some(operation) => {
                let route = (method.clone(), operation.path.clone());
                recorded.insert(route.clone());
                if not_ported.entries().contains(&route) {
                    plan.not_ported += 1;
                } else {
                    plan.to_replay.push(format!("{} ({method} {})", golden.name, operation.path));
                }
            }
        }
    }
    plan.operations_recorded = recorded.len();
    plan
}
