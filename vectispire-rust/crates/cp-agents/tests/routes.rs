//! The authorization coverage of the agents' seventeen routes, **enumerated from the router**, on MySQL 9.4 and
//! PostgreSQL 17 — so that a route added tomorrow is covered without anybody remembering to list it.
//!
//! - **The table:** every `/api/v1/agent/*` route takes an agent key and nothing else; every `/api/v1/admin/agents*`
//!   route takes an administrator. Eight and nine of them, as Java's two controllers have.
//! - **The callers who are not the route's:** an account of the role `USER`, an administrator's session and an
//!   administrator's integration key are sent every protocol route, and an agent's key every administration route;
//!   none of them is ever answered a success.
//! - **One agent's scan is not another's:** what a scan's routes do — the heartbeat, the result, the failure report —
//!   sent by an agent that did not claim it is the 409 Java answers, and leaves the scan with the agent that holds it.
//!   A result that resolves a target's backlog is the operation attestation exists to guard; an agent reaching another's
//!   scan would not need to forge anything.
//!
//! The answers' exact bytes, a disabled agent's 401 among them, are Java's recorded traffic's to hold
//! (`tests/golden.rs`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use axum::body::Body;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use vectispire_cp_db::{Db, Engine};
use vectispire_cp_http::access::Access;
use vectispire_cp_http::credentials::StaticCredentials;
use vectispire_cp_http::principal::Account;
use vectispire_cp_http::routes::RouteDecl;
use vectispire_cp_http::{ApiKeyScope, Principal, Role};

use support::{Migrated, agent, clean, compose, container, count, scan, status, system_clock};

const AGENT_A: &str = "coverage-agent-a";
const AGENT_B: &str = "coverage-agent-b";

/// The table, as the module registers it: building it runs no handler, so a pool that never connects is enough.
fn table() -> Vec<RouteDecl> {
    let composed = compose(&support::unreachable(), system_clock());
    vectispire_cp_agents::routes(composed.agents).iter().map(|entry| entry.decl().clone()).collect()
}

#[tokio::test]
async fn every_route_declares_its_caller() {
    let table = table();
    let protocol: Vec<_> = table.iter().filter(|r| r.path.starts_with("/api/v1/agent/")).collect();
    let admin: Vec<_> = table.iter().filter(|r| r.path.starts_with("/api/v1/admin/agents")).collect();
    assert_eq!(protocol.len() + admin.len(), table.len(), "every route is a protocol or an administration route");
    assert_eq!((protocol.len(), admin.len()), (8, 9), "Java's AgentsController and AgentsAdminController");
    for route in protocol {
        assert_eq!(route.access, Access::AgentKey, "{} {} is the agents' alone", route.method, route.path);
    }
    for route in admin {
        assert_eq!(route.access, Access::Administrator, "{} {} is an administrator's", route.method, route.path);
    }
}

fn account(username: &str, role: Role) -> Account {
    Account { username: username.to_owned(), role: Some(role), must_change_password: false }
}

fn request(method: &str, uri: &str, header: (&str, &str)) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header.0, header.1)
        .header("Content-Type", "application/json")
        .body(Body::from("{}"))
        .unwrap()
}

fn concrete(path: &str, scan: i64, agent: uuid::Uuid) -> String {
    path.replace("{scanId}", &scan.to_string())
        .replace("{id}", &agent.to_string())
        .replace("{hash}", "0000")
        .replace("{digest}", "0000")
}

async fn send(router: &axum::Router, method: &str, uri: &str, header: (&str, &str)) -> (StatusCode, String) {
    let response = router.clone().oneshot(request(method, uri, header)).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn claimed_by(db: &Db, scan: i64) -> Option<String> {
    support::text(db, &format!("select claimed_by from t_scan where id = {scan}")).await
}

async fn suite(engine: Engine) {
    let migrated = Migrated::start(engine).await;
    let db = migrated.connect().await;
    clean(&db).await;
    let a = agent(&db, AGENT_A, "delegated").await;
    agent(&db, AGENT_B, "delegated").await;
    let image = container(&db, "coverage").await;
    let held = scan(&db, None, Some(image), "pending", 0).await;

    let credentials = StaticCredentials::default()
        .key("key-agent-a", Principal::agent(AGENT_A))
        .key("key-agent-b", Principal::agent(AGENT_B))
        .session("tok-user", Principal::session(account("coverage-user", Role::User)))
        .session("tok-admin", Principal::session(account("coverage-admin", Role::Admin)))
        .key(
            "key-admin",
            Principal::integration(
                account("coverage-admin", Role::Admin),
                "key-1",
                vec![ApiKeyScope::Read, ApiKeyScope::Scan, ApiKeyScope::Export],
            ),
        );
    let composed = compose(&db, system_clock());
    let router = support::router(&db, composed.targets, composed.scanning, composed.agents, credentials, "everyone");

    let (claimed, _) = send(&router, "GET", "/api/v1/agent/jobs", ("X-API-Key", "key-agent-a")).await;
    assert_eq!(claimed, StatusCode::OK, "{engine}: agent A claims the scan");
    let holder = claimed_by(&db, held).await;
    assert!(holder.is_some(), "{engine}: the scan is held");

    let strangers = [
        ("a USER's session", ("Authorization", "Bearer tok-user")),
        ("an administrator's session", ("Authorization", "Bearer tok-admin")),
        ("an administrator's key", ("X-API-Key", "key-admin")),
    ];
    let mut reached = 0;
    for route in table() {
        let uri = concrete(&route.path, held, a);
        if route.path.starts_with("/api/v1/agent/") {
            for (who, header) in strangers {
                let (answered, body) = send(&router, &route.method, &uri, header).await;
                assert!(
                    !answered.is_success(),
                    "{engine}: {who} was answered {answered} by {} {}: {body}",
                    route.method,
                    route.path
                );
                reached += 1;
            }
        } else {
            let (answered, body) = send(&router, &route.method, &uri, ("X-API-Key", "key-agent-a")).await;
            assert!(
                !answered.is_success(),
                "{engine}: an agent's key was answered {answered} by {} {}: {body}",
                route.method,
                route.path
            );
            reached += 1;
        }
    }
    assert_eq!(reached, 8 * 3 + 9, "{engine}: every route was sent its strangers");

    for (method, path) in [
        ("POST", format!("/api/v1/agent/jobs/{held}/heartbeat")),
        ("POST", format!("/api/v1/agent/jobs/{held}/result")),
        ("POST", format!("/api/v1/agent/jobs/{held}/failure")),
    ] {
        let body = if path.ends_with("/failure") { r#"{"attempt":1,"reason":"x","kind":"transient"}"# } else { "{}" };
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(&path)
                    .header("X-API-Key", "key-agent-b")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT, "{engine}: agent B on agent A's scan, {method} {path}");
        assert_eq!(claimed_by(&db, held).await, holder, "{engine}: the scan stays agent A's after {path}");
        assert_eq!(status(&db, held).await, "scanning", "{engine}: and stays running");
    }
    assert_eq!(count(&db, "select count(*) from t_finding").await, 0, "{engine}: nothing of agent B's was written");

    db.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    suite(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_postgresql() {
    if !vectispire_cp_db::testing::runs_on(Engine::PostgreSql) {
        return;
    }
    suite(Engine::PostgreSql).await;
}
