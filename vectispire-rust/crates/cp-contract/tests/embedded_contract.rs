//! The real contract: the 0.11.1 line's `openapi.json`, as embedded.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use serde_json::{Value, json};
use vectispire_cp_contract::{
    Allowlist, Check, Document, Finding, Published, RouteDecl, Schemas, assert_none, check_published, check_routes,
    fill_parameters, path_parameters, split_parameter,
};

#[test]
fn the_embedded_document_is_the_one_the_port_targets() {
    let document = Document::embedded();
    assert_eq!(document.operations().len(), 311, "operations");
    let paths: BTreeSet<&str> = document.operations().iter().map(|operation| operation.path.as_str()).collect();
    assert_eq!(paths.len(), 245, "paths");
    assert_eq!(document.default_security(), ["BearerAuth"]);
    assert!(
        document.operation("GET", "/api/v1/projects/{projectId}/checklists/contacts").is_some(),
        "the 0.11.1 contacts route"
    );
}

#[test]
fn every_operation_id_of_the_document_is_unique_and_every_published_one_survives() {
    let document = Document::embedded();
    let findings = check_published(&document, &Published::embedded(), None);
    assert_none(&findings);
    assert!(Published::embedded().entries().len() >= 300, "the published list was read");
}

/// A router serving nothing misses exactly the routes that have left the list — which the modules that serve them
/// hold to the document where their routes are composed (`cp-targets`' `tests/contract.rs` for the twenty-nine of
/// task 2.6), and the binary's registry will once it carries them (task 2.11).
#[test]
fn a_router_that_serves_nothing_misses_exactly_the_ported_routes() {
    let document = Document::embedded();
    let nothing: Vec<RouteDecl> = Vec::new();
    let allowlist = Allowlist::embedded();
    let findings = check_routes(&document, &nothing, &allowlist);
    let ported = document.operations().len() - allowlist.entries().len();
    assert_eq!(findings.len(), ported, "{findings:#?}");
    assert!(findings.iter().all(|finding| matches!(finding, Finding::NotServed { .. })), "{findings:#?}");
}

#[test]
fn without_the_allowlist_every_documented_route_is_missing() {
    let document = Document::embedded();
    let nothing: Vec<RouteDecl> = Vec::new();
    let findings = check_routes(&document, &nothing, &Allowlist::none());
    assert_eq!(findings.len(), 311);
}

#[test]
fn a_concrete_request_finds_its_operation_and_a_literal_segment_beats_a_parameter() {
    let document = Document::embedded();
    let contacts = document.find("get", "/api/v1/projects/42/checklists/contacts").unwrap();
    assert_eq!(contacts.operation_id, "checklistContacts");
    assert!(document.find("GET", "/api/v1/no/such/route").is_none());
    assert!(document.find("PATCH", "/api/v1/projects/42/checklists/contacts").is_none(), "another method");
    // `/things/export` and `/things/{id}` style collisions: whichever literal route exists wins.
    for operation in document.operations() {
        let concrete = fill_parameters(&operation.path, "zz-not-a-literal");
        let found = document.find(&operation.method, &concrete).unwrap();
        assert_eq!(found.path, operation.path, "{} {concrete}", operation.method);
    }
}

#[test]
fn every_schema_the_document_gives_an_operation_compiles() {
    // A `$ref` that resolves nowhere, or a keyword the validator refuses, would make a check say
    // "invalid" about a body that is fine — or, worse, nothing about one that is not.
    let document = Document::embedded();
    let schemas = Schemas::of(&document);
    let mut checked = 0;
    for operation in document.operations() {
        let media = operation.request.iter().chain(operation.responses.values().flatten());
        for media in media {
            if let Some(schema) = &media.schema
                && let Err(errors) = schemas.validate(schema, &Value::Null)
            {
                checked += 1;
                assert!(
                    errors.iter().all(|error| !error.message.contains("does not compile")),
                    "{} {} {}: {:?}",
                    operation.method,
                    operation.path,
                    media.media_type,
                    errors
                );
            }
        }
    }
    assert!(checked > 100, "the schemas were exercised ({checked})");
}

fn contact(account_name: Value, warning: Value) -> Value {
    json!({
        "projectId": 7, "draft": true, "revision": null,
        "profiles": [ { "profile": "PO", "label": "PO", "openLines": 2, "accountId": 5, "accountName": account_name, "warning": warning } ]
    })
}

#[test]
fn a_response_of_the_real_contract_is_valid_and_a_wrong_one_names_the_field() {
    let document = Document::embedded();
    let schemas = Schemas::of(&document);
    let ok = contact(json!("Ada"), json!("no_email"));
    schemas.validate_named("ChecklistContactsView", &ok).unwrap();

    let mut wrong = ok.clone();
    wrong["profiles"][0]["openLines"] = json!("two");
    let errors = schemas.validate_named("ChecklistContactsView", &wrong).unwrap_err();
    assert!(errors.iter().any(|error| error.instance_path == "/profiles/0/openLines"), "{errors:?}");

    let mut absent = ok;
    absent.as_object_mut().unwrap().remove("projectId");
    assert!(schemas.validate_named("ChecklistContactsView", &absent).is_err(), "a required field");
}

#[test]
fn a_nullable_enum_that_does_not_list_null_rejects_the_null_the_java_application_sends() {
    // Pinned, not excused: on the 0.11.1 line `warning` is `type: [string, null]` with an `enum` that
    // lacks `null`, so the Java application's own `"warning": null` violates its own document. The
    // 0.12 contract adds `null` to those enums; until then a replay turns the leniency on.
    let document = Document::embedded();
    let null_warning = contact(json!("Ada"), Value::Null);

    let strict = Schemas::of(&document);
    assert!(strict.validate_named("ChecklistContactsView", &null_warning).is_err());

    let lenient = Schemas::of(&document).admitting_null_in_nullable_enums(true);
    lenient.validate_named("ChecklistContactsView", &null_warning).unwrap();
    let mut other = contact(json!("Ada"), json!("not-a-warning"));
    assert!(
        lenient.validate_named("ChecklistContactsView", &other).is_err(),
        "the leniency admits null and nothing else"
    );
    other["profiles"][0]["warning"] = json!("cannot_fill");
    lenient.validate_named("ChecklistContactsView", &other).unwrap();
}

#[test]
fn the_real_operation_of_a_route_checks_the_status_and_media_type_of_its_answer() {
    let document = Document::embedded();
    let schemas = Schemas::of(&document);
    let operation = document.find("GET", "/api/v1/projects/7/checklists/contacts").unwrap();
    let body = contact(json!("Ada"), json!("no_email"));
    assert_eq!(schemas.check_response(operation, 200, Some("application/json;charset=UTF-8"), &body), Check::Valid);
    assert!(matches!(
        schemas.check_response(operation, 404, Some("application/problem+json"), &json!({})),
        Check::Undeclared(_)
    ));
    assert!(matches!(
        schemas.check_response(operation, 200, Some("application/pdf"), &Value::Null),
        Check::NotChecked(_)
    ));
}

#[test]
fn a_parameter_inside_a_segment_is_a_parameter_and_still_matches() {
    // `/api/v1/scorecards/badges/{token}.svg` — the one template whose parameter has a suffix.
    let document = Document::embedded();
    assert_eq!(path_parameters("/api/v1/scorecards/badges/{token}.svg"), ["token"]);
    assert_eq!(path_parameters("/a/{x}/b/{y}"), ["x", "y"]);
    assert_eq!(fill_parameters("/api/v1/scorecards/badges/{token}.svg", "abc"), "/api/v1/scorecards/badges/abc.svg");
    let badge = document.find("GET", "/api/v1/scorecards/badges/abc.svg").unwrap();
    assert_eq!(badge.path, "/api/v1/scorecards/badges/{token}.svg");
    assert!(document.find("GET", "/api/v1/scorecards/badges/abc.png").is_none());
    assert!(document.find("GET", "/api/v1/scorecards/badges/.svg").is_none(), "an empty parameter is not a parameter");
}

#[test]
fn a_parameter_may_have_a_literal_before_it_as_well_as_after_it() {
    assert_eq!(split_parameter("{id}"), Some(("", "id", "")));
    assert_eq!(split_parameter("v{n}.json"), Some(("v", "n", ".json")));
    assert_eq!(split_parameter("literal"), None);
    assert_eq!(path_parameters("/files/v{n}.json/{id}"), ["n", "id"]);
    assert_eq!(fill_parameters("/files/v{n}.json", "2"), "/files/v2.json");
}
