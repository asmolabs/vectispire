//! Bodies against the toy contract: media types, status classes, and the three ways a schema says
//! "or null".

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::toy_document;
use serde_json::{Value, json};
use vectispire_cp_contract::{Check, Schemas};

fn thing() -> Value {
    json!({ "id": 7, "name": "seven", "tags": ["a"] })
}

#[test]
fn a_valid_answer_passes_and_the_error_names_the_place() {
    let document = toy_document();
    let schemas = Schemas::of(&document);
    let operation = document.operation("GET", "/api/v1/things/{id}").unwrap();
    assert_eq!(schemas.check_response(operation, 200, Some("application/json"), &thing()), Check::Valid);

    let Check::Invalid(errors) =
        schemas.check_response(operation, 200, Some("application/json"), &json!({ "id": "x", "name": 1 }))
    else {
        panic!("expected an invalid answer");
    };
    let places: Vec<&str> = errors.iter().map(|error| error.instance_path.as_str()).collect();
    assert!(places.contains(&"/id") && places.contains(&"/name"), "{places:?}");
}

#[test]
fn a_required_field_that_is_missing_is_an_error_and_null_is_not_missing() {
    let document = toy_document();
    let schemas = Schemas::of(&document);
    schemas.validate_named("Thing", &json!({ "id": 1, "name": null })).unwrap();
    assert!(schemas.validate_named("Thing", &json!({ "id": 1 })).is_err());
}

#[test]
fn the_three_encodings_of_or_null_all_admit_null_and_nothing_else() {
    let schemas = Schemas::of(&toy_document());
    // `type: [string, null]` (the Java generator), `oneOf [$ref, null]` (0.12), `nullable: true` (3.0).
    schemas.validate_named("Thing", &json!({ "id": 1, "name": null, "owner": null, "legacy": null })).unwrap();
    schemas
        .validate_named("Thing", &json!({ "id": 1, "name": "n", "owner": { "login": "ada" }, "legacy": "x" }))
        .unwrap();
    for bad in [
        json!({ "id": 1, "name": 5 }),
        json!({ "id": 1, "name": "n", "owner": 5 }),
        json!({ "id": 1, "name": "n", "legacy": 5 }),
    ] {
        assert!(schemas.validate_named("Thing", &bad).is_err(), "{bad}");
    }
}

#[test]
fn formats_are_checked_and_unknown_ones_are_not() {
    let schemas = Schemas::of(&toy_document());
    schemas
        .validate_named("Thing", &json!({ "id": 1, "name": "n", "created": "2026-10-16T07:27:05.123456Z" }))
        .unwrap();
    assert!(schemas.validate_named("Thing", &json!({ "id": 1, "name": "n", "created": "yesterday" })).is_err());
    // `int64` is not a JSON Schema format: it must not reject anything.
    schemas.validate_named("Thing", &json!({ "id": 9_007_199_254_740_993_i64, "name": "n" })).unwrap();
}

#[test]
fn the_declared_media_type_is_picked_by_specificity_and_a_wildcard_serves_json() {
    let document = toy_document();
    let schemas = Schemas::of(&document);
    // `*/*` declares the list's schema and the actual type is `application/json`.
    let list = document.operation("GET", "/api/v1/things").unwrap();
    assert_eq!(schemas.check_response(list, 200, Some("application/json"), &json!([thing()])), Check::Valid);
    assert!(matches!(schemas.check_response(list, 200, Some("application/json"), &json!({})), Check::Invalid(_)));
    // No content type given: the first JSON schema declared is used.
    assert_eq!(schemas.check_response(list, 200, None, &json!([thing()])), Check::Valid);
}

#[test]
fn a_problem_document_matches_the_suffix_wildcard_of_its_media_type() {
    let document = toy_document();
    let schemas = Schemas::of(&document);
    let get = document.operation("GET", "/api/v1/things/{id}").unwrap();
    assert_eq!(
        schemas.check_response(get, 404, Some("application/problem+json"), &json!({ "status": 404 })),
        Check::Valid
    );
    assert!(matches!(
        schemas.check_response(get, 404, Some("application/problem+json"), &json!({ "detail": "x" })),
        Check::Invalid(_)
    ));
}

#[test]
fn a_status_the_document_does_not_declare_is_counted_and_a_binary_body_is_not_checked() {
    let document = toy_document();
    let schemas = Schemas::of(&document);
    let get = document.operation("GET", "/api/v1/things/{id}").unwrap();
    assert!(matches!(schemas.check_response(get, 500, Some("application/json"), &json!({})), Check::Undeclared(_)));
    let export = document.operation("GET", "/api/v1/things/export").unwrap();
    assert!(matches!(schemas.check_response(export, 200, Some("text/csv"), &Value::Null), Check::NotChecked(_)));
    let delete = document.operation("DELETE", "/api/v1/things/{id}").unwrap();
    assert!(
        matches!(schemas.check_response(delete, 204, None, &Value::Null), Check::NotChecked(_)),
        "no content declared"
    );
}

#[test]
fn a_request_body_is_checked_against_the_operation_that_reads_it() {
    let document = toy_document();
    let schemas = Schemas::of(&document);
    let create = document.operation("POST", "/api/v1/things").unwrap();
    assert_eq!(schemas.check_request(create, Some("application/json"), &thing()), Check::Valid);
    assert!(matches!(
        schemas.check_request(create, Some("application/json"), &json!({ "name": "no id" })),
        Check::Invalid(_)
    ));
    let list = document.operation("GET", "/api/v1/things").unwrap();
    assert!(matches!(schemas.check_request(list, None, &Value::Null), Check::Undeclared(_)));
}

#[test]
fn a_schema_that_points_outside_the_document_is_an_error_and_never_a_download() {
    let schemas = Schemas::of(&toy_document());
    let errors = schemas.validate(&json!({ "$ref": "https://example.invalid/schema.json" }), &json!(1)).unwrap_err();
    assert!(!errors.is_empty());
    let missing = schemas.validate_named("NoSuchSchema", &json!(1)).unwrap_err();
    assert!(!missing.is_empty());
}

#[derive(serde::Serialize)]
struct Thing {
    id: i64,
    name: Option<String>,
    tags: Vec<String>,
}

#[test]
fn a_handler_type_is_checked_by_what_it_serializes_to() {
    let schemas = Schemas::of(&toy_document());
    schemas.assert_serializes_as("Thing", &Thing { id: 7, name: None, tags: vec!["a".into()] }).unwrap();

    #[derive(serde::Serialize)]
    struct Drifted {
        id: String,
    }
    assert!(schemas.assert_serializes_as("Thing", &Drifted { id: "7".into() }).is_err());
}
