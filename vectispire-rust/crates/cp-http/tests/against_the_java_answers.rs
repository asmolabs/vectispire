//! This crate's HTTP layer held to what the published control plane answered.
//!
//! `tests/golden/java/` is the 0.11.0-rc.3 server's answer to each request below, recorded by `golden/capture.sh`.
//! **Status, headers and body are compared; nothing here is read from a description.** What is *not* compared, and why:
//!
//! * `Date` — changes every second; `Last-Modified` — a placeholder in the golden, the file's mtime here;
//! * `Content-Length` and `Transfer-Encoding` — framing, which the server (Tomcat there, hyper here) chooses: the
//!   Java side sends a chunked body for a handler's problem and a length for the chain's, hyper sends a length for both. The
//!   bytes of the body are compared, which is what a client reads;
//! * the order of the headers — the Java side writes the interface's `Last-Modified` before the security headers and a
//!   problem's `Content-Type` after them; no client depends on either;
//! * `Allow`'s order — compared as a set (Spring lists "POST, GET", this crate sorts);
//! * the body of a golden marked `<N bytes>` (the interface's files: the test directory holds its own) and of the few
//!   goldens whose body is data this crate does not produce (a PEM key, a repository list).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use axum::body::Body;
use common::*;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;
use vectispire_cp_http::chain::ChainConfig;

struct Golden {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

fn golden(name: &str) -> Golden {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/java").join(format!("{name}.http"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let (head, body) = text.split_once("\n\n").expect("a head and a body");
    let mut lines = head.lines();
    let status =
        lines.next().expect("a status line").split_whitespace().next().expect("a status").parse().expect("a number");
    let headers = lines
        .map(|line| {
            let (name, value) = line.split_once(": ").expect("a header");
            (name.to_ascii_lowercase(), value.to_owned())
        })
        .collect();
    Golden { status, headers, body: body.to_owned() }
}

const FRAMING: [&str; 5] = ["date", "content-length", "transfer-encoding", "last-modified", "connection"];

fn comparable(headers: &[(String, String)]) -> BTreeSet<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| !FRAMING.contains(&name.as_str()))
        .map(|(name, value)| {
            if name == "allow" {
                let mut methods: Vec<&str> = value.split(',').map(str::trim).collect();
                methods.sort_unstable();
                (name.clone(), methods.join(", "))
            } else {
                (name.clone(), value.clone())
            }
        })
        .collect()
}

/// Whether the golden's body is to be compared: not the interface's files, not data this crate does not make.
fn body_compared(golden: &Golden, name: &str) -> bool {
    let placeholder = golden.body.starts_with('<') && golden.body.ends_with(" bytes>");
    let data =
        matches!(name, "public-key-anonymous" | "api-key-accepted" | "metrics-admin" | "api-key-create-response");
    !placeholder && !data
}

/// A wait is timing, not behaviour: the same refusal says 1 or 5 seconds depending on when the capture ran. What a wait *is*
/// — six seconds a token, rounded down, never under one — is asserted with a hand-moved clock in `limiters.rs`.
fn without_the_wait(text: &str) -> String {
    let waits = regex::Regex::new(r#"(in )\d+( seconds)|("retryAfterSeconds":)\d+"#).expect("a pattern");
    waits.replace_all(text, "${1}${3}<n>${2}").into_owned()
}

async fn holds(app: &App, name: &str, request: http::Request<Body>) {
    let expected = golden(name);
    let head = request.method() == http::Method::HEAD;
    let (status, headers, body) = text(send(app, request).await).await;
    assert_eq!(status.as_u16(), expected.status, "{name}: status");
    let wait_header = |name: &str| matches!(name, "retry-after" | "x-rate-limit-retry-after-seconds");
    let got: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| {
            let name = name.as_str().to_ascii_lowercase();
            let value = if wait_header(&name) { "<n>".to_owned() } else { value.to_str().expect("text").to_owned() };
            (name, value)
        })
        .collect();
    let expected = Golden {
        headers: expected
            .headers
            .into_iter()
            .map(|(n, v)| if wait_header(&n) { (n, "<n>".to_owned()) } else { (n, v) })
            .collect(),
        body: without_the_wait(&expected.body),
        ..expected
    };
    let body = without_the_wait(&body);
    let (want, have) = (comparable(&expected.headers), comparable(&got));
    assert_eq!(
        have,
        want,
        "{name}: headers\n  only here: {:?}\n  only in Java: {:?}",
        have.difference(&want).collect::<Vec<_>>(),
        want.difference(&have).collect::<Vec<_>>()
    );
    // A HEAD has no body to compare: the server drops it, and the router handed to a test has no server in front of it.
    if !head && body_compared(&expected, name) {
        assert_eq!(body, expected.body, "{name}: body");
    }
}

fn get(path: &str) -> http::Request<Body> {
    request("GET", path, &[], Body::empty())
}

fn get_with(path: &str, headers: &[(&str, &str)]) -> http::Request<Body> {
    request("GET", path, headers, Body::empty())
}

fn authorized(method: &str, path: &str, token: &str, body: Body) -> http::Request<Body> {
    request(method, path, &[("authorization", &bearer(token)), ("content-type", "application/json")], body)
}

#[tokio::test]
async fn the_chains_own_refusals_are_the_java_ones() {
    let app = app();
    holds(&app, "api-route-anonymous", get("/api/v1/repositories")).await;
    holds(&app, "unmapped-api-anonymous", get("/api/v1/nothing-here")).await;
    holds(&app, "metrics-anonymous", get("/actuator/metrics")).await;
    holds(&app, "api-docs-anonymous", get("/v3/api-docs")).await;
    holds(&app, "bearer-unknown", get_with("/api/v1/repositories", &[("authorization", "Bearer not-a-real-token")]))
        .await;
    holds(&app, "bearer-not-bearer-scheme", get_with("/api/v1/repositories", &[("authorization", "Basic YTpi")])).await;
    holds(&app, "role-refused", get_with("/api/v1/users", &[("authorization", &bearer(USER))])).await;
    holds(&app, "metrics-not-administrator", get_with("/actuator/metrics", &[("authorization", &bearer(USER))])).await;
    holds(
        &app,
        "default-body-limit-declared",
        request(
            "POST",
            "/api/v1/projects",
            &[("authorization", &bearer(ADMIN)), ("content-type", "application/json"), ("content-length", "1048577")],
            Body::empty(),
        ),
    )
    .await;
}

#[tokio::test]
async fn the_firewalls_and_the_containers_refusals_are_the_java_ones_with_no_security_headers() {
    let app = app();
    holds(&app, "firewall-double-slash", get("/api/v1//projects")).await;
    holds(&app, "firewall-semicolon", get("/api/v1/projects;x=1")).await;
    holds(&app, "firewall-encoded-traversal", get("/api/v1/%2e%2e/projects")).await;
    holds(&app, "firewall-encoded-slash", get("/api/v1/projects%2Fx")).await;
}

#[tokio::test]
async fn the_actuators_open_and_administrator_routes_are_the_java_ones() {
    let app = app();
    holds(&app, "health-anonymous", get("/actuator/health")).await;
    holds(&app, "metrics-admin", get_with("/actuator/metrics", &[("authorization", &bearer(ADMIN))])).await;
    holds(&app, "public-key-anonymous", get("/api/v1/crypto/public-key.pub")).await;
}

#[tokio::test]
async fn the_agent_route_answers_a_problem_of_its_own_to_a_caller_with_no_agent_key() {
    let app = app();
    holds(&app, "agent-route-anonymous", get("/api/v1/agent/jobs")).await;
}

#[tokio::test]
async fn a_password_change_owed_confines_the_account_as_the_java_chain_does() {
    let app = app();
    holds(&app, "password-change-pending", get_with("/api/v1/repositories", &[("authorization", &bearer(PENDING))]))
        .await;
    holds(&app, "role-refused-pending", get_with("/api/v1/users", &[("authorization", &bearer(PENDING))])).await;
}

#[tokio::test]
async fn an_integration_key_reaches_only_what_accepts_it() {
    let app = app();
    holds(&app, "api-key-not-accepted", get_with("/api/v1/users", &[("authorization", &bearer(READ_KEY))])).await;
    holds(&app, "api-key-not-accepted-header", get_with("/api/v1/users", &[("x-api-key", READ_KEY)])).await;
    holds(&app, "api-key-accepted", get_with("/api/v1/repositories", &[("authorization", &bearer(READ_KEY))])).await;
    holds(
        &app,
        "api-key-scope-missing",
        request("POST", "/api/v1/repositories/1/scan", &[("authorization", &bearer(READ_KEY))], Body::empty()),
    )
    .await;
}

#[tokio::test]
async fn the_handlers_problems_are_the_java_ones() {
    let app = app();
    holds(&app, "ok-json", authorized("GET", "/api/v1/repositories", ADMIN, Body::empty())).await;
    holds(&app, "not-found-row", authorized("GET", "/api/v1/projects/987654321", ADMIN, Body::empty())).await;
    holds(&app, "method-not-allowed-authenticated", authorized("DELETE", "/api/v1/repositories", ADMIN, Body::empty()))
        .await;
    holds(&app, "bad-request-body", authorized("POST", "/api/v1/repositories", ADMIN, Body::from("[]"))).await;
    let repository = r#"{"url":"https://git.example.org/invented/vs-rs-http.git","name":"vs-rs-http"}"#;
    holds(&app, "conflict-typed", authorized("POST", "/api/v1/repositories", ADMIN, Body::from(repository))).await;
}

#[tokio::test]
async fn the_sign_in_route_refuses_what_the_java_one_refuses() {
    let app = app();
    let json = [("content-type", "application/json")];
    holds(&app, "login-bad-json", request("POST", "/api/v1/auth/login", &json, Body::from("{not json"))).await;
    holds(
        &app,
        "login-unsupported-media",
        request("POST", "/api/v1/auth/login", &[("content-type", "text/plain")], Body::from("x")),
    )
    .await;
    holds(&app, "login-method-not-allowed", request("DELETE", "/api/v1/auth/login", &[], Body::empty())).await;
    // Declared over the 16 KB the sign-in takes: the chain's own 413, before a byte is read.
    // (A request built by hand carries no length; the server would have set it, so the test does.)
    let declared = [("content-type", "application/json"), ("content-length", "16385")];
    holds(
        &app,
        "login-too-large-declared",
        request("POST", "/api/v1/auth/login", &declared, Body::from(vec![b' '; 16385])),
    )
    .await;
    // Not declared: counted as it is read, and refused by the extractor reading it, in the handler's shape.
    let chunks = (0..3).map(|_| Ok::<_, std::convert::Infallible>(bytes::Bytes::from(vec![b' '; 8192])));
    let chunked = Body::from_stream(futures_util::stream::iter(chunks));
    holds(&app, "login-too-large-chunked", request("POST", "/api/v1/auth/login", &json, chunked)).await;
}

#[tokio::test]
async fn the_sign_in_throttle_answers_as_the_java_one_does() {
    let app = app();
    let attempt = || {
        request(
            "POST",
            "/api/v1/auth/login",
            &[("content-type", "application/json")],
            Body::from(r#"{"username":"nobody","password":"x"}"#),
        )
    };
    for _ in 0..10 {
        assert_eq!(send(&app, attempt()).await.status(), 401);
    }
    // The Java run was refused with one second to wait (`Retry-After: 1`, `retryAfterSeconds: 1`): a token takes six, and
    // 4.5 of them had gone by — the wait is 1.5 seconds, and both sides round it down.
    app.clock.advance(Duration::from_millis(4500));
    holds(&app, "login-throttled", attempt()).await;
}

#[tokio::test]
async fn the_interface_is_served_as_the_java_one_is() {
    let dir = interface_dir();
    let app = app_with(ChainConfig::default(), Some(dir.path()));
    holds(&app, "spa-index", get("/")).await;
    holds(&app, "spa-index-html", get("/index.html")).await;
    holds(&app, "spa-deep-link-1", get("/projects")).await;
    holds(&app, "spa-deep-link-3", get("/projects/1/checklist")).await;
    holds(&app, "spa-deep-link-4", get("/a/b/c/d")).await;
    holds(&app, "spa-dotted-missing", get("/missing.png")).await;
    holds(&app, "spa-assets-missing", get("/assets/missing.png")).await;
    holds(&app, "spa-favicon", get("/favicon.ico")).await;
    holds(&app, "spa-i18n", get("/i18n/en.json")).await;
    holds(&app, "spa-script", get("/main-TEST.js")).await;
    // Only a GET is let through without a credential: a HEAD of the same file is the chain's 401.
    holds(&app, "spa-script-head", request("HEAD", "/main-TEST.js", &[], Body::empty())).await;
}

#[tokio::test]
async fn what_the_firewall_and_the_container_refuse_beyond_the_first_four_is_the_java_set() {
    let app = app();
    for (name, path) in [
        ("firewall-encoded-percent", "/api/v1/a%25b"),
        ("firewall-encoded-semicolon", "/api/v1/a%3Bb"),
        ("firewall-encoded-backslash", "/api/v1/a%5Cb"),
        ("firewall-raw-backslash", "/api/v1/a\\b"),
        ("firewall-bad-escape", "/api/v1/%zz"),
        ("firewall-dot-segment", "/api/v1/./repositories"),
        ("firewall-dot-dot-segment", "/api/v1/../repositories"),
        // These two are *not* refused by the Java server: they reach the chain and are answered 401.
        ("firewall-control-character", "/api/v1/a%01b"),
        ("firewall-non-ascii", "/api/v1/a%C3%A9b"),
        ("firewall-trailing-slash", "/api/v1/repositories/"),
    ] {
        match http::Uri::try_from(path) {
            Ok(uri) => holds(&app, name, get(&uri.to_string())).await,
            // A path the HTTP stack will not even parse never reaches a router: hyper answers 400 first.
            Err(_) => assert_eq!(golden(name).status, 400, "{name}"),
        }
    }
}

#[tokio::test]
async fn the_spas_patterns_hold_at_their_edges() {
    let dir = interface_dir();
    let app = app_with(ChainConfig::default(), Some(dir.path()));
    for (name, path) in [
        ("spa-trailing-slash", "/projects/"),
        ("spa-api-bare", "/api"),
        ("spa-actuator-bare", "/actuator"),
        ("spa-dotless-near-actuator", "/actuator2"),
        ("spa-three-deep-slash", "/a/b/c/"),
        ("spa-api-subpath", "/api/foo/bar"),
        ("scim-anonymous", "/scim/v2/Users"),
    ] {
        holds(&app, name, get(path)).await;
    }
}

#[tokio::test]
async fn a_head_an_options_and_a_trailing_slash_are_answered_as_spring_answers_them() {
    let app = app();
    holds(&app, "head-authenticated", authorized("HEAD", "/api/v1/repositories", ADMIN, Body::empty())).await;
    holds(&app, "options-authenticated", authorized("OPTIONS", "/api/v1/repositories", ADMIN, Body::empty())).await;
    holds(&app, "options-anonymous", request("OPTIONS", "/api/v1/repositories", &[], Body::empty())).await;
    holds(&app, "trailing-slash-authenticated", authorized("GET", "/api/v1/repositories/", ADMIN, Body::empty())).await;
}
