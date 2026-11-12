//! Replaying recorded traffic: clean when the server answers as recorded, and every kind of
//! difference — status, header, body, key order, number text, rows — a named failure.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::routing::get;
use common::{toy_control_plane, toy_document};
use vectispire_cp_contract::{
    AxumServer, Document, FailureKind, Golden, Json, Normaliser, Replay, Request, Response, Schemas, Server,
    ServerError, load_dir, replay,
};

fn fixtures() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/goldens"))
}

fn toy_server() -> AxumServer {
    AxumServer::new(toy_control_plane().router())
}

fn golden(text: &str) -> Golden {
    Golden::from_json(Path::new("inline.json"), text).unwrap()
}

fn replaying<'a>(document: &'a Document, schemas: &'a Schemas) -> Replay<'a> {
    Replay {
        document,
        schemas,
        normaliser: Normaliser::standard(),
        require_db_effects: false,
        ignore_extra_headers: false,
        check_recorded: true,
    }
}

async fn run_one(text: &str) -> vectispire_cp_contract::Report {
    let document = toy_document();
    let schemas = Schemas::of(&document);
    replaying(&document, &schemas).run(&[golden(text)], &mut toy_server()).await
}

const GET: &str = r#"{
  "name": "get",
  "request": { "method": "GET", "path": "/api/v1/things/7" },
  "response": { "status": 200, "headers": { "content-type": "application/json" },
                "body": { "id": 7, "name": "seven", "tags": ["a", "b"] } }
}"#;

#[tokio::test]
async fn the_recorded_traffic_replays_clean_against_a_server_that_keeps_the_contract() {
    let document = toy_document();
    let schemas = Schemas::of(&document);
    let report = replay(fixtures(), &mut toy_server(), &document, &schemas).await.unwrap();
    report.assert_clean();
    assert_eq!(report.total, 5, "the manifest is not a golden");
    assert_eq!(
        report.schema_checked, 3,
        "the three JSON answers the server sent were checked against the document, the CSV and the 204 were not"
    );
}

#[tokio::test]
async fn a_golden_as_recorded_is_clean() {
    let report = run_one(GET).await;
    report.assert_clean();
}

#[tokio::test]
async fn another_status_is_named_with_both() {
    let report = run_one(&GET.replace("\"status\": 200", "\"status\": 404")).await;
    assert!(matches!(report.failures[0].kind, FailureKind::Status { expected: 404, actual: 200 }), "{report}");
}

#[tokio::test]
async fn a_changed_value_a_missing_key_and_an_extra_key_are_named_by_pointer() {
    let report = run_one(&GET.replace("\"seven\"", "\"sept\"")).await;
    let text = report.to_string();
    assert!(text.contains("body /name"), "{text}");

    let report = run_one(&GET.replace(r#""tags": ["a", "b"]"#, r#""tags": ["a", "b"], "extra": 1"#)).await;
    assert!(report.to_string().contains("body /extra: expected, absent"), "{report}");

    let report =
        run_one(&GET.replace(r#"{ "id": 7, "name": "seven", "tags": ["a", "b"] }"#, r#"{ "id": 7, "name": "seven" }"#))
            .await;
    assert!(report.to_string().contains("body /tags: present, not expected"), "{report}");
}

#[tokio::test]
async fn the_order_of_the_keys_is_compared_as_recorded_and_can_be_turned_off_by_the_golden() {
    let reordered = GET.replace(
        r#"{ "id": 7, "name": "seven", "tags": ["a", "b"] }"#,
        r#"{ "name": "seven", "id": 7, "tags": ["a", "b"] }"#,
    );
    let report = run_one(&reordered).await;
    assert!(report.to_string().contains("keys in the order"), "{report}");
    let unpinned = reordered.replace(r#""status": 200,"#, r#""status": 200, "keyOrder": false,"#);
    run_one(&unpinned).await.assert_clean();
}

#[tokio::test]
async fn the_spelling_of_a_number_is_part_of_the_answer() {
    let report = run_one(&GET.replace(r#""id": 7"#, r#""id": 7.0"#)).await;
    assert!(report.to_string().contains("body /id: 7, expected 7.0"), "{report}");
}

#[tokio::test]
async fn a_header_that_differs_is_missing_or_unexpected_is_named() {
    let report = run_one(&GET.replace("application/json", "application/json;charset=UTF-8")).await;
    assert!(
        matches!(&report.failures[0].kind, FailureKind::Headers(lines) if lines.iter().any(|line| line.contains("content-type"))),
        "{report}"
    );

    let extra = GET.replace(
        r#""headers": { "content-type": "application/json" }"#,
        r#""headers": { "content-type": "application/json", "cache-control": "no-store" }"#,
    );
    let report = run_one(&extra).await;
    assert!(report.to_string().contains("header cache-control: absent"), "{report}");
}

#[tokio::test]
async fn a_server_header_the_golden_does_not_have_is_a_difference_unless_extra_headers_are_ignored() {
    let document = toy_document();
    let schemas = Schemas::of(&document);
    let router = toy_control_plane().router().layer(axum::middleware::map_response(
        |mut response: axum::response::Response| async move {
            response.headers_mut().insert("x-frame-options", "DENY".parse().unwrap());
            response
        },
    ));
    let strict = replaying(&document, &schemas).run(&[golden(GET)], &mut AxumServer::new(router.clone())).await;
    assert!(strict.to_string().contains("header x-frame-options: \"DENY\" sent, not recorded"), "{strict}");

    let mut lenient = replaying(&document, &schemas);
    lenient.ignore_extra_headers = true;
    lenient.run(&[golden(GET)], &mut AxumServer::new(router)).await.assert_clean();
}

#[tokio::test]
async fn a_body_that_is_not_json_is_compared_as_text() {
    let export = r#"{
      "request": { "method": "GET", "path": "/api/v1/things/export" },
      "response": { "status": 200, "headers": { "content-type": "text/csv" }, "bodyText": "id,name\n7,seven\n" }
    }"#;
    run_one(export).await.assert_clean();
    let report = run_one(&export.replace("7,seven", "7,sept")).await;
    assert!(matches!(report.failures[0].kind, FailureKind::Body(_)), "{report}");
}

#[tokio::test]
async fn an_expected_body_the_server_did_not_send_and_the_reverse_are_failures() {
    let none = r#"{ "request": { "method": "DELETE", "path": "/api/v1/things/7" }, "response": { "status": 204 } }"#;
    run_one(none).await.assert_clean();
    let with_body = none.replace(r#""status": 204"#, r#""status": 204, "body": { "a": 1 }"#);
    assert!(matches!(run_one(&with_body).await.failures[0].kind, FailureKind::Body(_)));
    let get_without_body =
        GET.replace(r#""body": { "id": 7, "name": "seven", "tags": ["a", "b"] }"#, r#""headers2": {}"#);
    assert!(matches!(run_one(&get_without_body).await.failures[0].kind, FailureKind::Body(_)));
}

#[tokio::test]
async fn a_request_that_reaches_no_operation_of_the_document_is_a_failure_of_the_recording() {
    let report = run_one(&GET.replace("/api/v1/things/7", "/api/v1/nothing/7")).await;
    assert!(
        matches!(&report.failures[0].kind, FailureKind::UnknownRoute { path, .. } if path == "/api/v1/nothing/7"),
        "{report}"
    );
}

#[tokio::test]
async fn the_replayed_answer_is_checked_against_the_schema_as_the_server_sent_it() {
    // A server whose `id` is a string: the answer violates the document, whatever was recorded.
    let document = toy_document();
    let schemas = Schemas::of(&document);
    let drifting = toy_control_plane();
    let _ = drifting;
    let router = axum::Router::new().route(
        "/api/v1/things/{id}",
        get(|| async { ([("content-type", "application/json")], r#"{"id":"7","name":"seven","tags":["a","b"]}"#) }),
    );
    let mut run = replaying(&document, &schemas);
    run.check_recorded = false;
    let recorded_with_string_id = GET.replace(r#""id": 7"#, r#""id": "7""#);
    let report = run.run(&[golden(&recorded_with_string_id)], &mut AxumServer::new(router)).await;
    assert!(matches!(&report.failures[0].kind, FailureKind::Schema { which: "replayed", .. }), "{report}");
    assert!(report.to_string().contains("/id"));
}

#[tokio::test]
async fn a_recorded_answer_that_breaks_the_schema_fails_when_the_recording_is_checked() {
    let report = run_one(&GET.replace(r#""id": 7"#, r#""id": "seven""#)).await;
    assert!(matches!(&report.failures[0].kind, FailureKind::Schema { which: "recorded", .. }), "{report}");
}

#[tokio::test]
async fn an_undeclared_status_is_counted_and_not_failed() {
    let router = axum::Router::new().route(
        "/api/v1/things/{id}",
        get(|| async {
            (axum::http::StatusCode::NOT_FOUND, [("content-type", "application/json")], r#"{"anything":true}"#)
        }),
    );
    let document = toy_document();
    let schemas = Schemas::of(&document);
    let recorded = GET
        .replace("\"status\": 200", "\"status\": 404")
        .replace(r#"{ "id": 7, "name": "seven", "tags": ["a", "b"] }"#, r#"{ "anything": true }"#);
    let mut run = replaying(&document, &schemas);
    run.check_recorded = false;
    let report = run.run(&[golden(&recorded)], &mut AxumServer::new(router)).await;
    report.assert_clean();
    assert_eq!(report.undeclared, 1);
}

// ---- normalisation

#[tokio::test]
async fn normalisation_json_names_what_the_recorder_replaced_and_the_same_rules_apply_to_the_server() {
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/goldens-normalised"));
    let (goldens, normaliser) = load_dir(dir).unwrap();
    assert_eq!(goldens.len(), 1);

    let router = axum::Router::new().route(
        "/api/v1/things/{id}",
        get(|| async {
            (
                [("content-type", "application/json"), ("x-served-by", "node-3")],
                r#"{"id":7,"name":"item-33","tags":["a","b"]}"#,
            )
        }),
    );
    let document = toy_document();
    let schemas = Schemas::of(&document);
    let mut run = replaying(&document, &schemas);
    run.normaliser = normaliser;
    run.check_recorded = false; // `"<id>"` is not an integer
    run.run(&goldens, &mut AxumServer::new(router)).await.assert_clean();
}

#[test]
fn the_standard_normalisation_replaces_timestamps_uuids_and_api_keys() {
    let normaliser = Normaliser::standard();
    assert_eq!(
        normaliser.text("at 2026-10-16T07:27:05.123456Z and 2026-10-16T09:27:05+02:00"),
        "at <timestamp> and <timestamp>"
    );
    assert_eq!(normaliser.text("7f9c1d2e-0a4b-4c3d-8e5f-6a7b8c9d0e1f"), "<uuid>");
    assert_eq!(normaliser.text("Bearer zsk_AbC-123_x"), "Bearer <api-key>");
    assert_eq!(normaliser.text("plain"), "plain");
    // Idempotent: a recorder that normalised already costs nothing.
    assert_eq!(normaliser.text("<timestamp> <uuid>"), "<timestamp> <uuid>");
}

#[test]
fn a_normalisation_file_that_does_not_compile_is_refused_with_the_pattern() {
    let error = Normaliser::from_json(r#"{"stringPatterns":[{"regex":"(","placeholder":"x"}]}"#).unwrap_err();
    assert!(error.contains('('), "{error}");
    assert!(Normaliser::from_json(r#"{"keyPlaceholders":[{"key":"a"}]}"#).is_err(), "a rule without a placeholder");
}

// ---- the rows a request touched

fn with_rows(rows_after: &str) -> String {
    GET.replace(r#""name": "get","#, &format!(r#""name": "rows", "db": {{ "before": {{}}, "after": {rows_after} }},"#))
}

#[derive(Clone, Default)]
struct Database(Arc<Mutex<Option<String>>>);

#[tokio::test]
async fn the_rows_a_request_touched_are_compared_with_the_recorded_ones() {
    let document = toy_document();
    let schemas = Schemas::of(&document);
    let database = Database::default();
    *database.0.lock().unwrap() = Some(r#"{"t_thing":[{"id":7,"name":"seven"}]}"#.to_owned());
    let dumped = database.clone();
    let mut server =
        toy_server().dumping(move |_| Ok(dumped.0.lock().unwrap().as_deref().map(|text| Json::parse(text).unwrap())));

    let recorded = with_rows(r#"{ "t_thing": [ { "id": 7, "name": "seven" } ] }"#);
    replaying(&document, &schemas).run(&[golden(&recorded)], &mut server).await.assert_clean();

    let wrong = with_rows(r#"{ "t_thing": [ { "id": 7, "name": "sept" } ] }"#);
    let report = replaying(&document, &schemas).run(&[golden(&wrong)], &mut server).await;
    assert!(matches!(&report.failures[0].kind, FailureKind::Rows(_)), "{report}");
    assert!(report.to_string().contains("rows /t_thing/0/name"));
}

#[tokio::test]
async fn a_server_that_cannot_dump_rows_is_counted_and_fails_when_the_replay_requires_them() {
    let document = toy_document();
    let schemas = Schemas::of(&document);
    let recorded = with_rows(r#"{ "t_thing": [] }"#);

    let counted = replaying(&document, &schemas).run(&[golden(&recorded)], &mut toy_server()).await;
    counted.assert_clean();
    assert_eq!(counted.rows_not_compared, 1);

    let mut strict = replaying(&document, &schemas);
    strict.require_db_effects = true;
    let report = strict.run(&[golden(&recorded)], &mut toy_server()).await;
    assert!(matches!(report.failures[0].kind, FailureKind::RowsNotAvailable), "{report}");
}

#[tokio::test]
async fn the_seeding_hook_is_called_with_the_golden_before_it_is_sent() {
    let document = toy_document();
    let schemas = Schemas::of(&document);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let mut server = toy_server().seeding(move |golden| {
        log.lock().unwrap().push(golden.name.clone());
        Ok(())
    });
    replaying(&document, &schemas).run(&[golden(GET)], &mut server).await.assert_clean();
    assert_eq!(*seen.lock().unwrap(), ["get"]);

    let mut failing = toy_server().seeding(|_| Err("the database is down".to_owned()));
    let report = replaying(&document, &schemas).run(&[golden(GET)], &mut failing).await;
    assert!(
        matches!(&report.failures[0].kind, FailureKind::Server(message) if message.contains("database is down")),
        "{report}"
    );
}

// ---- reading goldens

#[test]
fn a_golden_is_read_with_its_query_headers_and_body_and_its_path_with_an_inline_query() {
    let golden = golden(
        r#"{ "request": { "method": "post", "path": "/api/v1/things?a=1", "query": "b=two&c",
                           "headers": { "X": "y" }, "body": { "k": 1.50 } },
             "response": { "status": 201 } }"#,
    );
    assert_eq!(golden.request.method, "POST");
    assert_eq!(golden.request.path, "/api/v1/things");
    assert_eq!(golden.request.target(), "/api/v1/things?b=two&c=&a=1");
    assert_eq!(golden.name, "inline");
    let body = golden.request.body.unwrap().to_text();
    assert_eq!(body, r#"{"k":1.50}"#, "number text kept");
}

#[test]
fn a_query_given_as_an_object_is_percent_encoded() {
    let golden = golden(
        r#"{ "request": { "method": "GET", "path": "/p", "query": { "q": "a b&c" } }, "response": { "status": 200 } }"#,
    );
    assert_eq!(golden.request.target(), "/p?q=a%20b%26c");
}

#[test]
fn what_is_not_a_golden_is_refused_with_the_file_and_the_reason() {
    for (text, reason) in [
        ("not json", "not JSON"),
        (r#"{ "response": { "status": 200 } }"#, "no `request`"),
        (r#"{ "request": { "method": "GET", "path": "/" } }"#, "no `response`"),
        (r#"{ "request": { "path": "/" }, "response": { "status": 200 } }"#, "no `request.method`"),
        (
            r#"{ "request": { "method": "GET", "path": "/" }, "response": { "status": "ok" } }"#,
            "numeric `response.status`",
        ),
        (
            r#"{ "request": { "method": "GET", "path": "/", "query": 5 }, "response": { "status": 200 } }"#,
            "neither an object nor a string",
        ),
    ] {
        let error = Golden::from_json(Path::new("bad.json"), text).unwrap_err().to_string();
        assert!(error.contains("bad.json") && error.contains(reason), "{error}");
    }
}

#[test]
fn a_directory_of_goldens_is_read_in_path_order_and_a_missing_one_is_an_error() {
    let (goldens, _) = load_dir(fixtures()).unwrap();
    let names: Vec<&str> = goldens.iter().map(|golden| golden.name.as_str()).collect();
    assert_eq!(names, ["things/create", "things/delete", "things/export", "things/get", "things/list"]);
    assert!(load_dir(Path::new("/no/such/directory")).is_err());
}

// ---- a server of its own

struct Down;

impl Server for Down {
    async fn prepare(&mut self, _golden: &Golden) -> Result<(), ServerError> {
        Ok(())
    }

    async fn send(&mut self, _request: &Request) -> Result<Response, ServerError> {
        Err(ServerError("connection refused".to_owned()))
    }
}

#[tokio::test]
async fn a_server_that_cannot_answer_fails_the_golden_and_does_not_stop_the_replay() {
    let document = toy_document();
    let schemas = Schemas::of(&document);
    let report = replaying(&document, &schemas).run(&[golden(GET), golden(GET)], &mut Down).await;
    assert_eq!(report.failures.len(), 2);
    assert!(matches!(&report.failures[0].kind, FailureKind::Server(message) if message.contains("connection refused")));
}
