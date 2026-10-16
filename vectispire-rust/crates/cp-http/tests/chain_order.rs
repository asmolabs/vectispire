//! The order of the layers is the behaviour; these tests say where each one is.
//!
//! `CHAIN` names the layers outermost first. A request that passes every layer is driven through the assembled router and the
//! order in which they ran is compared with it — so that a layer moved "for tidiness" fails a test that names where it was
//! and why that matters (`chain.rs`).

mod common;

use axum::body::Body;
use common::*;
use vectispire_cp_http::chain::CHAIN;

#[tokio::test]
async fn a_request_that_passes_everything_meets_the_layers_in_the_documented_order() {
    let app = app();
    let response = send(&app, request("GET", "/api/v1/whoami", &[("authorization", &bearer(ADMIN))], Body::empty())).await;
    assert_eq!(response.status(), 200);
    assert_eq!(app.trace.take(), CHAIN);
}

#[tokio::test]
async fn the_chain_lists_the_java_filter_chain_and_the_route_stages() {
    assert_eq!(
        CHAIN,
        [
            "firewall",
            "client-address",
            "headers",
            "login-limit",
            "webhook-limit",
            "body-limit",
            "bearer-limit",
            "bearer",
            "access",
            "problems",
            "password-change",
            "credential-confinement",
            "role",
        ]
    );
}

#[tokio::test]
async fn the_firewall_answers_before_anything_else_has_run() {
    let app = app();
    let response = send(&app, request("GET", "/api/v1//whoami", &[], Body::empty())).await;
    assert_eq!(response.status(), 400);
    assert_eq!(app.trace.take(), ["firewall"]);
}

#[tokio::test]
async fn a_request_with_no_credential_stops_at_access_before_the_route_is_looked_at() {
    let app = app();
    let response = send(&app, request("GET", "/api/v1/whoami", &[], Body::empty())).await;
    assert_eq!(response.status(), 401);
    let seen = app.trace.take();
    assert_eq!(seen.last().copied(), Some("access"));
    assert!(!seen.contains(&"password-change"), "the route's gate runs for a matched route that got past access: {seen:?}");
}

#[tokio::test]
async fn an_unmapped_path_and_a_wrong_method_are_answered_before_a_routes_gate_as_spring_answers_them_before_an_interceptor() {
    let app = app();
    send(&app, request("GET", "/api/v1/nothing-here", &[("authorization", &bearer(ADMIN))], Body::empty())).await;
    assert!(!app.trace.take().contains(&"password-change"));
    send(&app, request("DELETE", "/api/v1/repositories", &[("authorization", &bearer(PENDING))], Body::empty())).await;
    assert!(!app.trace.take().contains(&"password-change"), "a pending password does not turn a 405 into a 403");
}

#[tokio::test]
async fn the_headers_wrap_everything_after_them_the_limiters_refusals_included() {
    let app = app();
    for _ in 0..10 {
        send(&app, request("POST", "/api/v1/auth/login", &[("content-type", "application/json")], Body::from("{}"))).await;
    }
    let refused = send(&app, request("POST", "/api/v1/auth/login", &[("content-type", "application/json")], Body::from("{}"))).await;
    assert_eq!(refused.status(), 429);
    assert!(refused.headers().contains_key("content-security-policy"));
    // And the firewall's refusal, written before them, carries none.
    let firewall = send(&app, request("GET", "/a//b", &[], Body::empty())).await;
    assert!(!firewall.headers().contains_key("content-security-policy"));
}
