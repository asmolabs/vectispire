//! The router against the toy document: every way they can disagree is a named finding, and the
//! probe asks the router itself.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use axum::routing::{get, post, put};
use common::{TOY_PUBLISHED, toy_control_plane, toy_document};
use vectispire_cp_contract::{
    Allowlist, Document, Finding, Published, RecordingRouter, RouteDecl, assert_none, assert_router, check_published,
    check_routes, probe, render,
};

fn ok() -> RecordingRouter {
    toy_control_plane()
}

fn find(findings: &[Finding], wanted: impl Fn(&Finding) -> bool) -> bool {
    findings.iter().any(wanted)
}

#[test]
fn a_router_that_keeps_the_contract_has_no_finding() {
    assert_none(&check_routes(&toy_document(), &ok(), &Allowlist::none()));
}

#[test]
fn a_documented_route_the_router_lacks_is_not_served_and_the_allowlist_excuses_it_once() {
    let document = toy_document();
    let partial = RecordingRouter::new().route(
        RouteDecl::new("GET", "/api/v1/things", "listThings").query("limit", false).header("X-Trace", false),
        get(|| async {}),
    );
    let findings = check_routes(&document, &partial, &Allowlist::none());
    assert!(find(
        &findings,
        |finding| matches!(finding, Finding::NotServed { path, .. } if path == "/api/v1/things/{id}")
    ));
    assert!(find(
        &findings,
        |finding| matches!(finding, Finding::MethodNotServed { method, path } if method == "POST" && path == "/api/v1/things")
    ));
}

#[test]
fn a_route_the_document_does_not_list_is_not_documented() {
    let extra = toy_control_plane().route(RouteDecl::new("GET", "/api/v1/secret", "secret"), get(|| async {}));
    let findings = check_routes(&toy_document(), &extra, &Allowlist::none());
    assert_eq!(findings, vec![Finding::NotDocumented { method: "GET".into(), path: "/api/v1/secret".into() }]);
}

#[test]
fn a_route_registered_twice_is_reported() {
    let twice = RecordingRouter::new();
    let routes = vec![RouteDecl::new("GET", "/a", "a"), RouteDecl::new("GET", "/a", "a")];
    let _ = twice;
    let findings = check_routes(&toy_document(), &routes, &Allowlist::none());
    assert!(find(&findings, |finding| matches!(finding, Finding::DuplicateRoute { .. })));
}

#[test]
fn another_operation_id_is_named_with_both() {
    let renamed: Vec<RouteDecl> = ok_routes()
        .into_iter()
        .map(|mut route| {
            if route.operation_id == "getThing" {
                route.operation_id = "thing".into();
            }
            route
        })
        .collect();
    let findings = check_routes(&toy_document(), &renamed, &Allowlist::none());
    assert_eq!(
        findings,
        vec![Finding::OperationId {
            method: "GET".into(),
            path: "/api/v1/things/{id}".into(),
            served: "thing".into(),
            documented: "getThing".into()
        }]
    );
}

fn ok_routes() -> Vec<RouteDecl> {
    use vectispire_cp_contract::RouteSource;
    ok().routes()
}

#[test]
fn a_parameter_missing_extra_or_with_another_required_flag_is_a_difference() {
    let document = toy_document();
    let change = |edit: fn(&mut RouteDecl)| -> Vec<Finding> {
        let routes: Vec<RouteDecl> = ok_routes()
            .into_iter()
            .map(|mut route| {
                if route.operation_id == "listThings" {
                    edit(&mut route);
                }
                route
            })
            .collect();
        check_routes(&document, &routes, &Allowlist::none())
    };
    let missing = change(|route| route.query.clear());
    assert!(
        find(
            &missing,
            |finding| matches!(finding, Finding::Parameters { difference, .. } if difference.contains("documented, not declared: query limit"))
        ),
        "{}",
        render(&missing)
    );
    let extra =
        change(|route| route.query.push(vectispire_cp_contract::ParamDecl { name: "offset".into(), required: false }));
    assert!(find(
        &extra,
        |finding| matches!(finding, Finding::Parameters { difference, .. } if difference.contains("declared, not documented: query offset"))
    ));
    let required = change(|route| route.query[0].required = true);
    assert!(
        find(&required, |finding| matches!(finding, Finding::Parameters { .. })),
        "a required flag is part of the contract"
    );
    let header = change(|route| route.headers.clear());
    assert!(find(
        &header,
        |finding| matches!(finding, Finding::Parameters { difference, .. } if difference.contains("header x-trace"))
    ));
}

#[test]
fn a_path_parameter_renamed_is_a_difference_because_the_document_names_it() {
    let routes: Vec<RouteDecl> = ok_routes()
        .into_iter()
        .map(|mut route| {
            if route.path == "/api/v1/things/{id}" {
                route.path = "/api/v1/things/{thingId}".into();
            }
            route
        })
        .collect();
    let findings = check_routes(&toy_document(), &routes, &Allowlist::none());
    assert!(find(
        &findings,
        |finding| matches!(finding, Finding::NotServed { path, .. } if path == "/api/v1/things/{id}")
    ));
    assert!(find(
        &findings,
        |finding| matches!(finding, Finding::NotDocumented { path, .. } if path == "/api/v1/things/{thingId}")
    ));
}

#[test]
fn security_is_compared_with_the_operations_own_or_the_documents() {
    let document = toy_document();
    let weaker: Vec<RouteDecl> = ok_routes()
        .into_iter()
        .map(|mut route| {
            if route.operation_id == "deleteThing" {
                route.security = vectispire_cp_contract::SecurityDecl::Schemes(vec!["BearerAuth".into()]);
            }
            route
        })
        .collect();
    let findings = check_routes(&document, &weaker, &Allowlist::none());
    assert_eq!(
        findings,
        vec![Finding::Security {
            method: "DELETE".into(),
            path: "/api/v1/things/{id}".into(),
            served: vec!["BearerAuth".into()],
            documented: vec!["ApiKeyAuth".into(), "BearerAuth".into()]
        }]
    );
    let anonymous: Vec<RouteDecl> = ok_routes()
        .into_iter()
        .map(|route| if route.operation_id == "listThings" { route.security(&[]) } else { route })
        .collect();
    let findings = check_routes(&document, &anonymous, &Allowlist::none());
    assert!(
        find(
            &findings,
            |finding| matches!(finding, Finding::Security { path, served, .. } if path == "/api/v1/things" && served.is_empty())
        ),
        "a route that drops the document's security"
    );
}

#[test]
fn the_allowlist_only_shrinks() {
    let document = toy_document();
    let partial: Vec<RouteDecl> = ok_routes().into_iter().filter(|route| route.operation_id != "deleteThing").collect();

    // The honest list: one route, ceiling one.
    let list = Allowlist::parse("DELETE /api/v1/things/{id}\n", "1");
    assert_none(&check_routes(&document, &partial, &list));

    // Served now, still listed: delete the line.
    let stale = Allowlist::parse("DELETE /api/v1/things/{id}\n", "1");
    let findings = check_routes(&document, &ok_routes(), &stale);
    assert_eq!(
        findings,
        vec![Finding::AllowlistedButServed { method: "DELETE".into(), path: "/api/v1/things/{id}".into() }]
    );

    // A route the document does not know cannot be parked there.
    let unknown = Allowlist::parse("DELETE /api/v1/things/{id}\nGET /api/v1/nope\n", "2");
    let findings = check_routes(&document, &partial, &unknown);
    assert_eq!(findings, vec![Finding::AllowlistUnknownRoute { method: "GET".into(), path: "/api/v1/nope".into() }]);

    // More entries than the ceiling: growth.
    let grown = Allowlist::parse("DELETE /api/v1/things/{id}\nGET /api/v1/things/export\n", "1");
    let fewer: Vec<RouteDecl> = ok_routes()
        .into_iter()
        .filter(|route| route.operation_id != "deleteThing" && route.operation_id != "exportThings")
        .collect();
    let findings = check_routes(&document, &fewer, &grown);
    assert_eq!(findings, vec![Finding::AllowlistGrew { entries: 2, ceiling: 1 }]);

    // Fewer entries than the ceiling: the slack is not for spending on another route.
    let slack = Allowlist::parse("DELETE /api/v1/things/{id}\n", "2");
    let findings = check_routes(&document, &partial, &slack);
    assert_eq!(findings, vec![Finding::CeilingNotLowered { entries: 1, ceiling: 2 }]);
}

#[test]
fn a_malformed_allowlist_line_and_a_malformed_ceiling_are_findings() {
    let list = Allowlist::parse("DELETE\nGET relative\nPOST /a extra\n", "many");
    let findings = check_routes(&toy_document(), &ok_routes(), &list);
    assert_eq!(findings.iter().filter(|finding| matches!(finding, Finding::Malformed { .. })).count(), 4);
}

#[test]
fn the_text_of_an_allowlist_is_every_route_the_router_does_not_serve() {
    let document = toy_document();
    let partial: Vec<RouteDecl> = ok_routes().into_iter().filter(|route| route.operation_id != "deleteThing").collect();
    let text = Allowlist::text_for(&document, &partial);
    let lines: Vec<&str> = text.lines().filter(|line| !line.starts_with('#')).collect();
    assert_eq!(lines, vec!["DELETE /api/v1/things/{id}"]);
}

// ---- the published operation ids

#[test]
fn the_published_ids_of_the_toy_contract_hold() {
    assert_none(&check_published(&toy_document(), &Published::parse(TOY_PUBLISHED), Some(&ok())));
}

#[test]
fn a_published_id_that_is_renamed_removed_or_duplicated_is_named() {
    let document = toy_document();
    let renamed = Published::parse("GET /api/v1/things oldName\n");
    assert_eq!(
        check_published(&document, &renamed, None),
        vec![Finding::PublishedChanged {
            method: "GET".into(),
            path: "/api/v1/things".into(),
            published: "oldName".into(),
            documented: "listThings".into()
        }]
    );
    let removed = Published::parse("GET /api/v1/gone goneId\n");
    assert_eq!(
        check_published(&document, &removed, None),
        vec![Finding::PublishedMissing {
            method: "GET".into(),
            path: "/api/v1/gone".into(),
            operation_id: "goneId".into()
        }]
    );
    let twice = Published::parse("GET /api/v1/things listThings\nGET /api/v1/things listThings\n");
    assert_eq!(
        check_published(&document, &twice, None),
        vec![Finding::PublishedDuplicate { method: "GET".into(), path: "/api/v1/things".into() }]
    );
    let malformed = Published::parse("GET /api/v1/things\n");
    assert!(matches!(check_published(&document, &malformed, None)[0], Finding::Malformed { .. }));
}

#[test]
fn the_router_must_register_a_published_route_under_its_published_id() {
    let renamed: Vec<RouteDecl> = ok_routes()
        .into_iter()
        .map(|mut route| {
            if route.operation_id == "listThings" {
                route.operation_id = "things".into();
            }
            route
        })
        .collect();
    let findings = check_published(&toy_document(), &Published::parse(TOY_PUBLISHED), Some(&renamed));
    assert_eq!(
        findings,
        vec![Finding::OperationId {
            method: "GET".into(),
            path: "/api/v1/things".into(),
            served: "things".into(),
            documented: "listThings".into()
        }]
    );
}

#[test]
fn two_operations_with_one_id_in_the_document_are_reported() {
    let text = common::TOY.replace("\"operationId\": \"getThing\"", "\"operationId\": \"listThings\"");
    let document = Document::parse(&text).unwrap();
    let findings = check_published(&document, &Published::parse(""), None);
    assert_eq!(findings, vec![Finding::DuplicateOperationId { operation_id: "listThings".into() }]);
}

// ---- the router itself

#[tokio::test]
async fn the_probe_finds_a_router_that_answers_every_documented_route() {
    let router = ok();
    assert_none(&probe(&router.router(), &toy_document(), &Allowlist::none()).await);
    assert_none(&assert_router(&router, &toy_document(), &Allowlist::none(), &Published::parse(TOY_PUBLISHED)).await);
}

#[tokio::test]
async fn the_probe_catches_a_declaration_that_the_router_does_not_keep() {
    // Declared as POST and DELETE, registered as PUT: the declaration table is clean, the router is not.
    let lying = RecordingRouter::new()
        .route(
            RouteDecl::new("GET", "/api/v1/things", "listThings").query("limit", false).header("X-Trace", false),
            get(|| async {}),
        )
        .route(RouteDecl::new("POST", "/api/v1/things", "createThing"), put(|| async {}))
        .route(RouteDecl::new("GET", "/api/v1/things/{id}", "getThing"), get(|| async {}))
        .route(
            RouteDecl::new("DELETE", "/api/v1/things/{id}", "deleteThing").security(&["ApiKeyAuth", "BearerAuth"]),
            put(|| async {}),
        )
        .route(RouteDecl::new("GET", "/api/v1/things/export", "exportThings"), get(|| async {}));
    assert_none(&check_routes(&toy_document(), &lying, &Allowlist::none()));
    let findings = probe(&lying.router(), &toy_document(), &Allowlist::none()).await;
    assert!(
        find(
            &findings,
            |finding| matches!(finding, Finding::MethodNotServed { method, path } if method == "POST" && path == "/api/v1/things")
        ),
        "{}",
        render(&findings)
    );
    assert!(find(
        &findings,
        |finding| matches!(finding, Finding::MethodNotServed { method, .. } if method == "DELETE")
    ));
}

#[tokio::test]
async fn the_probe_reports_a_route_with_no_handler_at_all_and_a_listed_route_that_is_served() {
    let partial = RecordingRouter::new()
        .route(
            RouteDecl::new("GET", "/api/v1/things", "listThings").query("limit", false).header("X-Trace", false),
            get(|| async {}),
        )
        .route(RouteDecl::new("POST", "/api/v1/things", "createThing"), post(|| async {}));
    let findings = probe(&partial.router(), &toy_document(), &Allowlist::none()).await;
    assert!(find(
        &findings,
        |finding| matches!(finding, Finding::NotServed { path, .. } if path == "/api/v1/things/{id}")
    ));
    assert!(find(
        &findings,
        |finding| matches!(finding, Finding::NotServed { path, .. } if path == "/api/v1/things/export")
    ));

    // Listed as not ported, yet answered: the probe says so too.
    let listed = Allowlist::parse("GET /api/v1/things\n", "1");
    let findings = probe(&partial.router(), &toy_document(), &listed).await;
    assert!(find(
        &findings,
        |finding| matches!(finding, Finding::AllowlistedButServed { method, path } if method == "GET" && path == "/api/v1/things")
    ));
}

#[tokio::test]
async fn a_handler_that_answers_404_is_a_route_and_not_a_missing_one() {
    use axum::http::StatusCode;
    let router = RecordingRouter::new()
        .route(RouteDecl::new("GET", "/api/v1/things/{id}", "getThing"), get(|| async { StatusCode::NOT_FOUND }));
    let not_ported = Allowlist::parse("GET /api/v1/things\nPOST /api/v1/things\nDELETE /api/v1/things/{id}\n", "3");
    let findings = probe(&router.router(), &toy_document(), &not_ported).await;
    // `/things/export` is answered — by `/things/{id}`, as it would be on the wire. That the literal
    // route has no handler of its own is for the declaration table to say, and it does:
    assert!(findings.is_empty(), "{}", render(&findings));
    let declared = check_routes(&toy_document(), &router, &not_ported);
    assert!(find(
        &declared,
        |finding| matches!(finding, Finding::NotServed { path, .. } if path == "/api/v1/things/export")
    ));
}
