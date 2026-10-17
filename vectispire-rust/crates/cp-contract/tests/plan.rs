//! What a replay owes, sorted before there is anything to replay against: a recording of a route not yet ported is
//! skipped, one of a route that has left the list is owed a replay, one no operation answers is outside the contract.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

use common::toy_document;
use vectispire_cp_contract::{Allowlist, Golden, load_dir, plan};

fn fixtures() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/goldens"))
}

fn golden(method: &str, path: &str) -> Golden {
    Golden::from_json(
        Path::new("inline.json"),
        &format!(
            r#"{{"name":"{method} {path}","request":{{"method":"{method}","path":"{path}"}},"response":{{"status":200}}}}"#
        ),
    )
    .unwrap()
}

#[test]
fn a_recording_of_a_route_not_yet_ported_is_skipped_and_owes_nothing() {
    let list = Allowlist::parse("GET /api/v1/things/{id}\nGET /api/v1/things\n", "2");
    let found = plan(&[golden("GET", "/api/v1/things/7"), golden("GET", "/api/v1/things")], &toy_document(), &list);
    assert_eq!((found.total, found.not_ported, found.operations_recorded), (2, 2, 2));
    assert!(found.owes_nothing());
    assert!(found.outside_contract.is_empty());
}

#[test]
fn the_day_a_route_leaves_the_list_its_recordings_are_owed_a_replay() {
    // `getThing` is ported (not on the list); `listThings` is not.
    let list = Allowlist::parse("GET /api/v1/things\n", "1");
    let found = plan(&[golden("GET", "/api/v1/things/7"), golden("GET", "/api/v1/things")], &toy_document(), &list);
    assert!(!found.owes_nothing());
    assert_eq!(found.to_replay.len(), 1, "{:?}", found.to_replay);
    assert!(found.to_replay[0].contains("GET /api/v1/things/{id}"), "{:?}", found.to_replay);
    assert_eq!(found.not_ported, 1);
}

#[test]
fn a_request_no_operation_answers_is_outside_the_contract_and_named_once() {
    let list = Allowlist::parse("", "0");
    let found = plan(
        &[golden("GET", "/actuator/health"), golden("GET", "/actuator/health"), golden("PATCH", "/api/v1/things/1")],
        &toy_document(),
        &list,
    );
    assert_eq!(found.outside_contract.len(), 2, "{:?}", found.outside_contract);
    assert!(found.outside_contract.contains("GET /actuator/health"));
    assert!(found.outside_contract.contains("PATCH /api/v1/things/1"));
    assert!(found.owes_nothing(), "outside the contract is reported, not owed");
}

#[test]
fn the_fixture_recordings_are_read_and_sorted() {
    let (goldens, _normaliser) = load_dir(fixtures()).unwrap();
    assert!(goldens.len() >= 4, "{} fixtures", goldens.len());
    let found = plan(&goldens, &toy_document(), &Allowlist::none());
    assert_eq!(found.total, goldens.len());
    // With nothing on the list, every recording of a documented route is owed.
    assert_eq!(found.to_replay.len() + found.outside_contract.len(), goldens.len());
}
