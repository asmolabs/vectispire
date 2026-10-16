//! What a credential may reach, asserted through the assembled chain: the role markers against every role, the credential
//! kinds against the routes that do and do not accept them, and the refusals' audit entries.
//!
//! `AuthorizationCoverageTest` and `RouteAuthorizationTest` are Phase 1's to port against the real routes; what is
//! pinned here is the machinery they will rely on, the way the Java `RouteAuthorizationTest` was not enough alone — it
//! enumerated annotations and never sent an anonymous request through the chain (`anOpenRouteIsReallyReachableWithoutCredentials`).

mod common;

use axum::body::Body;
use common::*;
use vectispire_cp_http::chain::ChainConfig;

async fn status_of(app: &App, path: &str, headers: &[(&str, &str)]) -> u16 {
    send(app, request("GET", path, headers, Body::empty())).await.status().as_u16()
}

async fn with(app: &App, path: &str, token: &str) -> u16 {
    status_of(app, path, &[("authorization", &bearer(token))]).await
}

#[tokio::test]
async fn each_marker_admits_the_roles_the_java_marker_names_and_refuses_the_others() {
    let app = app();
    // role → the markers it reaches
    let table: [(&str, [bool; 6]); 6] = [
        // administrator, governance-read, platform-governor, security-lead, write, account
        (ADMIN, [true, true, true, true, false, true]), // SUPERUSER
        (CISO, [false, true, false, true, true, true]),
        (CHAMPION, [false, false, false, false, true, true]),
        (AUDITOR, [false, true, false, false, false, true]),
        (USER, [false, false, false, false, true, true]),
        (UNREADABLE, [false, false, false, false, false, true]),
    ];
    let routes = ["administrator", "governance-read", "platform-governor", "security-lead", "write", "account"];
    for (token, reaches) in table {
        for (route, expected) in routes.iter().zip(reaches) {
            let got = with(&app, &format!("/api/v1/_t/{route}"), token).await;
            assert_eq!(got, if expected { 200 } else { 403 }, "{token} on {route}");
        }
    }
}

#[tokio::test]
async fn an_account_with_an_unreadable_role_is_signed_in_and_authorized_for_nothing() {
    let app = app();
    assert_eq!(with(&app, "/api/v1/_t/account", UNREADABLE).await, 200, "isAuthenticated() holds");
    assert_eq!(with(&app, "/api/v1/_t/write", UNREADABLE).await, 403, "and no role does: not the least privileged one");
}

#[tokio::test]
async fn an_anonymous_route_is_really_reachable_with_no_credential_and_a_marked_one_is_not() {
    let app = app();
    assert_eq!(status_of(&app, "/api/v1/_t/anonymous", &[]).await, 401, "it needs the chain's own rule too: only the listed paths are open");
    for (path, open) in [("/api/v1/crypto/public-key.pub", 200), ("/actuator/health", 200), ("/api/v1/_t/account", 401)] {
        assert_eq!(status_of(&app, path, &[]).await, open, "{path}");
    }
}

#[tokio::test]
async fn a_refusal_names_no_role_and_is_audited_with_who_where_and_with_what() {
    let app = app();
    let (status, _, body) = text(
        send(&app, request("GET", "/api/v1/_t/administrator", &[("authorization", &bearer(USER)), ("user-agent", "curl/8.0")], Body::empty())).await,
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(body, r#"{"title":"Forbidden","status":403,"detail":"This credential is not allowed to call this route.","instance":"/api/v1/_t/administrator"}"#);
    let denied = app.audit.denied.lock().expect("lock");
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0].path, "/api/v1/_t/administrator");
    assert_eq!(denied[0].who.as_deref(), Some("vs-rs-http-user"));
    assert_eq!(denied[0].address, "203.0.113.9");
    assert_eq!(denied[0].user_agent.as_deref(), Some("curl/8.0"));
    assert!(denied[0].detail.starts_with("Access denied:"));
}

#[tokio::test]
async fn the_actuator_beyond_health_takes_an_administrators_session_and_nothing_else() {
    let app = app();
    assert_eq!(with(&app, "/actuator/metrics", ADMIN).await, 200);
    assert_eq!(with(&app, "/actuator/metrics", AUDITOR).await, 403, "an auditor sees the audit log, not the metrics");
    assert_eq!(with(&app, "/actuator/metrics", PENDING).await, 403, "an administrator who owes a password change");
    assert_eq!(with(&app, "/actuator/metrics", READ_KEY).await, 403, "an integration key of an administrator's account");
    assert_eq!(with(&app, "/actuator/metrics", AGENT_KEY).await, 403, "an agent key");
    assert_eq!(status_of(&app, "/actuator/metrics", &[]).await, 401);
    assert_eq!(app.audit.denied.lock().expect("lock").len(), 4);
}

#[tokio::test]
async fn an_agent_key_reaches_the_agent_routes_and_only_those() {
    let app = app();
    assert_eq!(with(&app, "/api/v1/agent/_t", AGENT_KEY).await, 200);
    for route in ["account", "anonymous", "write"] {
        let (status, _, body) = text(send(&app, request("GET", &format!("/api/v1/_t/{route}"), &[("authorization", &bearer(AGENT_KEY))], Body::empty())).await).await;
        assert_eq!(status, 403, "{route}");
        assert!(body.contains("This route does not accept an agent key."), "{route}: {body}");
    }
}

#[tokio::test]
async fn an_agent_route_refuses_whoever_is_not_an_agent_in_the_agent_controllers_words() {
    let app = app();
    for headers in [vec![], vec![("authorization", "Bearer nope")]] {
        let (status, _, body) = text(send(&app, request("GET", "/api/v1/agent/_t", &headers, Body::empty())).await).await;
        assert_eq!(status, 401);
        assert_eq!(body, r#"{"detail":"API key absent, invalid, or without the \"agent\" scope.","instance":"/api/v1/agent/_t","status":401,"title":"Unauthorized"}"#);
    }
    assert_eq!(with(&app, "/api/v1/agent/_t", ADMIN).await, 401, "a session is not an agent");
    assert_eq!(with(&app, "/api/v1/agent/_t", READ_KEY).await, 403, "an integration key is refused by the confinement first");
}

#[tokio::test]
async fn an_integration_key_is_refused_where_no_marker_accepts_it_and_where_the_scope_is_missing() {
    let app = app();
    let (_, _, body) = text(send(&app, request("GET", "/api/v1/_t/account", &[("authorization", &bearer(READ_KEY))], Body::empty())).await).await;
    assert!(body.contains("This route does not accept an API key."));
    let (_, _, body) = text(send(&app, request("POST", "/api/v1/repositories/1/scan", &[("authorization", &bearer(READ_KEY))], Body::empty())).await).await;
    assert!(body.contains("This API key lacks the scan scope."));
    assert_eq!(with(&app, "/api/v1/repositories", READ_KEY).await, 200);
}

#[tokio::test]
async fn the_scim_token_is_a_principal_on_scim_and_nowhere_else() {
    let app = app();
    assert_eq!(with(&app, "/scim/v2/Users", SCIM_TOKEN).await, 200, "an administrator, on /scim");
    assert_eq!(with(&app, "/api/v1/users", SCIM_TOKEN).await, 401, "not recognised elsewhere: it falls through to the key lookup");
    assert_eq!(with(&app, "/api/v1/_t/account", SCIM_TOKEN).await, 401);
    assert_eq!(with(&app, "/scim/v2/Users", "wrong-token").await, 401);
}

#[tokio::test]
async fn the_api_key_header_is_a_key_alias_and_never_a_session_alias() {
    let app = app();
    assert_eq!(status_of(&app, "/api/v1/repositories", &[("x-api-key", READ_KEY)]).await, 200);
    assert_eq!(status_of(&app, "/api/v1/whoami", &[("x-api-key", ADMIN)]).await, 401, "a session token presented as a key is not looked at");
    // An `Authorization` header, even a useless one, means the alias is not consulted.
    assert_eq!(status_of(&app, "/api/v1/repositories", &[("authorization", "Bearer nope"), ("x-api-key", READ_KEY)]).await, 401);
}

#[tokio::test]
async fn a_password_change_owed_blocks_every_route_that_does_not_allow_it() {
    let app = app();
    assert_eq!(with(&app, "/api/v1/auth/me", PENDING).await, 200, "who am I stays reachable");
    for path in ["/api/v1/whoami", "/api/v1/_t/account", "/api/v1/repositories"] {
        let (status, _, body) = text(send(&app, request("GET", path, &[("authorization", &bearer(PENDING))], Body::empty())).await).await;
        assert_eq!(status, 403, "{path}");
        assert!(body.contains("A password change is required before any other action."), "{path}");
    }
}

#[tokio::test]
async fn a_scoped_route_receives_the_visibility_resolved_for_its_caller() {
    let app = app();
    let (status, _, body) = text(send(&app, request("GET", "/api/v1/scoped", &[("authorization", &bearer(CISO))], Body::empty())).await).await;
    assert_eq!((status.as_u16(), body.as_str()), (200, "ciso"));
    let (_, _, body) = text(send(&app, request("GET", "/api/v1/scoped", &[("authorization", &bearer(USER))], Body::empty())).await).await;
    assert_eq!(body, "vs-rs-http-user");
}

#[tokio::test]
async fn a_handler_asking_for_a_visibility_its_route_never_resolved_is_a_500_that_says_so() {
    let app = app();
    let (status, _, body) = text(send(&app, request("GET", "/api/v1/_t/misuse", &[("authorization", &bearer(ADMIN))], Body::empty())).await).await;
    assert_eq!(status, 500);
    assert!(body.contains("This route was registered without resolving a visibility."), "{body}");
}

#[tokio::test]
async fn the_api_documentation_is_closed_unless_somebody_opened_it() {
    let closed = app();
    assert_eq!(status_of(&closed, "/v3/api-docs", &[]).await, 401);
    assert_eq!(with(&closed, "/v3/api-docs", ADMIN).await, 200);
    let open = app_with(ChainConfig { anonymous_api_docs: true, ..ChainConfig::default() }, None);
    assert_eq!(status_of(&open, "/v3/api-docs", &[]).await, 200);
}

#[tokio::test]
async fn a_body_read_whole_by_a_handler_is_cut_at_its_routes_ceiling_with_the_handlers_413() {
    let app = app();
    let over = vec![b'x'; 1024 * 1024 + 1];
    let chunks = over.chunks(64 * 1024).map(|chunk| Ok::<_, std::convert::Infallible>(bytes::Bytes::copy_from_slice(chunk))).collect::<Vec<_>>();
    let (status, _, body) = text(send(&app, request("POST", "/api/v1/drain", &[("authorization", &bearer(ADMIN))], Body::from_stream(futures_util::stream::iter(chunks)))).await).await;
    assert_eq!(status, 413);
    assert!(body.contains("The request body is larger than the 1048576 bytes this route accepts."), "{body}");
    // A rule-set upload has 64 MB.
    let (status, _, body) = text(send(&app, request("POST", "/api/v1/rule-sets", &[("authorization", &bearer(ADMIN))], Body::from(vec![b'x'; 2 * 1024 * 1024]))).await).await;
    assert_eq!((status.as_u16(), body.as_str()), (200, "2097152 bytes"));
}
