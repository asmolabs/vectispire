//! The rest of the protocol through its routes, on a real database — what the replay reached only as far as the
//! Java suite's requests went (task 2.9's audit, 2026-10-21):
//!
//! - **hello** stores what the agent says of itself, trimmed as Java trims it, refuses a contract it cannot speak, and
//!   refuses a disabled agent;
//! - **a sign of life** is a poll that finds nothing or a lease renewal, but a poll soon after another writes nothing
//!   (`AgentLastSeenRoutesTest`);
//! - **the long poll** waits out its `wait` when the queue is empty, hands over a scan queued during it, and refuses a
//!   `wait` Spring cannot bind — before authentication, as the binding comes first;
//! - **a failure report** requeues, fails for good when permanent, applies once, belongs to the lease holder, and
//!   refuses a report naming no attempt (`AgentFailureReportRoutesTest`);
//! - **a database that cannot be read** while authenticating is a 500, not the 401 that blamed the agent's key.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod support;

use std::time::{Duration, Instant};

use axum::body::Body;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;
use vectispire_cp_db::{Db, Engine};
use vectispire_cp_http::credentials::StaticCredentials;
use vectispire_cp_http::principal::Principal;

use support::{
    Composed, Migrated, agent_as, attempts, clean, compose, container, count, exec, scan, status, system_clock, text,
};

const OWNER: &str = "agent-lifecycle-owner-token"; // gitleaks:allow — a test fixture
const OTHER: &str = "agent-lifecycle-other-token"; // gitleaks:allow — a test fixture
/// The rows the two keys are bound to: a key's principal names its agent by id.
const OWNER_ID: uuid::Uuid = uuid::Uuid::from_u128(0x6f77_6e65_7200_4000_8000_0000_0000_0001);
const OTHER_ID: uuid::Uuid = uuid::Uuid::from_u128(0x6f74_6865_7200_4000_8000_0000_0000_0002);
/// A second agent declared under the owner's name — a re-declaration to rotate a key, then the old one disabled.
const TWIN: &str = "agent-lifecycle-twin-token"; // gitleaks:allow — a test fixture
const TWIN_ID: uuid::Uuid = uuid::Uuid::from_u128(0x7477_696e_0000_4000_8000_0000_0000_0003);

fn router(db: &Db, composed: Composed) -> axum::Router {
    support::router(
        db,
        composed.targets,
        composed.scanning,
        composed.agents,
        StaticCredentials::default()
            .key(OWNER, Principal::agent("agent:owner", &OWNER_ID.to_string()))
            .key(OTHER, Principal::agent("agent:other", &OTHER_ID.to_string()))
            .key(TWIN, Principal::agent("agent:owner", &TWIN_ID.to_string())),
        "everyone",
    )
}

async fn send(router: &axum::Router, token: &str, method: &str, uri: &str, body: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("X-API-Key", token)
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) })
}

async fn agent_text(db: &Db, name: &str, column: &str) -> Option<String> {
    text(db, &format!("select {column} from t_agent where name = '{name}'")).await
}

/// `last_seen_at` as text, to the microsecond, on either engine.
async fn last_seen(db: &Db, name: &str) -> Option<String> {
    let cast = match db {
        Db::MySql(_) => "cast(last_seen_at as char)",
        Db::PostgreSql(_) => "to_char(last_seen_at, 'YYYY-MM-DD HH24:MI:SS.US')",
    };
    agent_text(db, name, cast).await
}

async fn set_last_seen(db: &Db, name: &str, at: &str) {
    exec(db, &format!("update t_agent set last_seen_at = '{at}' where name = '{name}'")).await;
}

fn utc(offset: time::Duration) -> String {
    let at = time::OffsetDateTime::now_utc() + offset;
    let format =
        time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:6]");
    at.format(&format).unwrap()
}

fn report(attempt: i64, reason: &str, kind: Option<&str>) -> String {
    let mut body = serde_json::json!({ "attempt": attempt, "reason": reason });
    if let Some(kind) = kind {
        body["kind"] = Value::String(kind.to_owned());
    }
    body.to_string()
}

async fn audited(db: &Db, operation: &str, containing: &str) -> i64 {
    count(
        db,
        &format!(
            "select count(*) from t_audit_log where operation_type = '{operation}' and description like '%{containing}%'"
        ),
    )
    .await
}

async fn suite(engine: Engine) {
    let migrated = Migrated::start(engine).await;
    let db = migrated.connect().await;

    // ── hello ──
    clean(&db).await;
    agent_as(&db, OWNER_ID, "owner", "local", true).await;
    let routes = router(&db, compose(&db, system_clock()));
    let (answered, body) = send(
        &routes,
        OWNER,
        "POST",
        "/api/v1/agent/hello",
        r#"{"hostname":"  build-01 \t","platform":"linux/amd64","version":" 2.0.0 ","scanner_engine":"","contract_version":" 1 "}"#,
    )
    .await;
    assert_eq!(answered, StatusCode::OK, "{engine}: hello: {body}");
    assert_eq!(agent_text(&db, "owner", "hostname").await.as_deref(), Some("build-01"), "{engine}: trimmed");
    assert_eq!(agent_text(&db, "owner", "version").await.as_deref(), Some("2.0.0"), "{engine}: trimmed");
    assert_eq!(agent_text(&db, "owner", "scanner_engine").await, None, "{engine}: blank is absent");
    assert_eq!(agent_text(&db, "owner", "contract_version").await.as_deref(), Some("1"), "{engine}: as announced");
    assert!(last_seen(&db, "owner").await.is_some(), "{engine}: hello is a sign of life");

    let (answered, body) = send(&routes, OWNER, "POST", "/api/v1/agent/hello", r#"{"contract_version":"999"}"#).await;
    assert_eq!(answered, StatusCode::CONFLICT, "{engine}: a contract it cannot speak: {body}");

    exec(&db, "update t_agent set enabled = false where name = 'owner'").await;
    let (answered, body) = send(&routes, OWNER, "POST", "/api/v1/agent/hello", r#"{"contract_version":"1"}"#).await;
    assert_eq!(answered, StatusCode::UNAUTHORIZED, "{engine}: disabled");
    assert_eq!(body["detail"], "Agent \"owner\" is disabled.", "{engine}");

    // ── the wait is bound before authentication, as Spring binds it ──
    let (answered, body) = send(&routes, OWNER, "GET", "/api/v1/agent/jobs?wait=thirty", "").await;
    assert_eq!(answered, StatusCode::BAD_REQUEST, "{engine}: an unbindable wait, even disabled");
    assert_eq!(body["detail"], "Failed to convert 'wait' with value: 'thirty'", "{engine}");
    exec(&db, "update t_agent set enabled = true where name = 'owner'").await;

    // ── a sign of life: an idle poll, but not one right after another ──
    set_last_seen(&db, "owner", "2000-01-01 00:00:00").await;
    let (answered, _) = send(&routes, OWNER, "GET", "/api/v1/agent/jobs", "").await;
    assert_eq!(answered, StatusCode::NO_CONTENT, "{engine}: nothing queued");
    assert!(last_seen(&db, "owner").await.unwrap().as_str() > "2020", "{engine}: an idle poll counts");

    let recent = utc(time::Duration::seconds(-5));
    set_last_seen(&db, "owner", &recent).await;
    send(&routes, OWNER, "GET", "/api/v1/agent/jobs", "").await;
    assert_eq!(last_seen(&db, "owner").await.as_deref(), Some(recent.as_str()), "{engine}: a recent sign is kept");

    // ── the long poll ──
    let started = Instant::now();
    let (answered, _) = send(&routes, OWNER, "GET", "/api/v1/agent/jobs?wait=1", "").await;
    let waited = started.elapsed();
    assert_eq!(answered, StatusCode::NO_CONTENT, "{engine}: nothing came");
    assert!(waited >= Duration::from_millis(900), "{engine}: the wait is served: {waited:?}");
    assert!(waited < Duration::from_secs(4), "{engine}: and not much more: {waited:?}");

    let image = container(&db, "img").await;
    let queueing = {
        let db = db.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1_200)).await;
            scan(&db, None, Some(image), "pending", 0).await
        })
    };
    let started = Instant::now();
    let (answered, task) = send(&routes, OWNER, "GET", "/api/v1/agent/jobs?wait=10", "").await;
    let queued = queueing.await.unwrap();
    assert_eq!(answered, StatusCode::OK, "{engine}: a scan queued during the wait is handed over");
    assert_eq!(task["scanId"], queued, "{engine}");
    assert!(started.elapsed() < Duration::from_secs(5), "{engine}: without waiting out the rest");

    // ── a heartbeat is a sign of life, and belongs to the lease holder ──
    agent_as(&db, OTHER_ID, "other", "local", true).await;
    set_last_seen(&db, "owner", "2000-01-01 00:00:00").await;
    let (answered, _) = send(&routes, OWNER, "POST", &format!("/api/v1/agent/jobs/{queued}/heartbeat"), "").await;
    assert_eq!(answered, StatusCode::NO_CONTENT, "{engine}: the lease renewed");
    assert!(last_seen(&db, "owner").await.unwrap().as_str() > "2020", "{engine}: a renewal counts");
    let (answered, body) = send(&routes, OTHER, "POST", &format!("/api/v1/agent/jobs/{queued}/heartbeat"), "").await;
    assert_eq!(answered, StatusCode::CONFLICT, "{engine}: not the other's");
    assert_eq!(body["detail"], "This scan is no longer yours: its lease was taken over.", "{engine}");

    // ── failure reports ──
    let failure = format!("/api/v1/agent/jobs/{queued}/failure");
    let (answered, _) = send(&routes, OWNER, "POST", &failure, r#"{"reason":"clone refused"}"#).await;
    assert_eq!(answered, StatusCode::BAD_REQUEST, "{engine}: no attempt named");
    let (answered, _) = send(&routes, OWNER, "POST", &failure, "not json").await;
    assert_eq!(answered, StatusCode::BAD_REQUEST, "{engine}: not JSON");
    let (answered, _) = send(&routes, OTHER, "POST", &failure, &report(1, "not mine", None)).await;
    assert_eq!(answered, StatusCode::CONFLICT, "{engine}: only the lease holder");
    assert_eq!(status(&db, queued).await, "scanning", "{engine}: and nothing changed");

    let (answered, body) = send(&routes, OWNER, "POST", &failure, &report(1, "The clone timed out.", None)).await;
    assert_eq!(answered, StatusCode::OK, "{engine}: requeued: {body}");
    assert_eq!(body["retried"], true, "{engine}");
    assert_eq!(body["permanent"], false, "{engine}");
    assert_eq!(body["attempt"], 1, "{engine}");
    assert_eq!(body["maxAttempts"], 3, "{engine}");
    assert!(body["retryAt"].is_string(), "{engine}: {body}");
    assert_eq!(status(&db, queued).await, "pending", "{engine}");
    assert_eq!(attempts(&db, queued).await, 1, "{engine}: the attempt counted");
    let (answered, _) = send(&routes, OWNER, "POST", &failure, &report(1, "again", None)).await;
    assert_eq!(answered, StatusCode::CONFLICT, "{engine}: applied once");
    assert_eq!(audited(&db, "AGENT_SCAN_FAILED", "a transient failure").await, 1, "{engine}");

    let permanent = scan(&db, None, Some(image), "pending", 0).await;
    let (answered, task) = send(&routes, OWNER, "GET", "/api/v1/agent/jobs", "").await;
    assert_eq!((answered, task["scanId"].as_i64()), (StatusCode::OK, Some(permanent)), "{engine}");
    let (answered, body) = send(
        &routes,
        OWNER,
        "POST",
        &format!("/api/v1/agent/jobs/{permanent}/failure"),
        &report(1, "The host key has changed.", Some("permanent")),
    )
    .await;
    assert_eq!(answered, StatusCode::OK, "{engine}: {body}");
    assert_eq!(body["retried"], false, "{engine}");
    assert_eq!(body["permanent"], true, "{engine}");
    assert!(body.get("retryAt").is_none_or(Value::is_null), "{engine}: {body}");
    assert_eq!(status(&db, permanent).await, "failed", "{engine}: failed at once");
    assert_eq!(audited(&db, "AGENT_SCAN_FAILED", "a permanent failure").await, 1, "{engine}");

    // ── a key is its own row's, never a namesake's (review 2026-11) ──
    // `t_agent.name` is not unique. Found by name, one of the two keys below acted as the other row: the disabled
    // agent's key kept working as the enabled one, or the enabled one was refused as disabled — whichever row the
    // engine returned first.
    agent_as(&db, TWIN_ID, "owner", "local", false).await;
    let (answered, body) = send(&routes, TWIN, "POST", "/api/v1/agent/hello", r#"{"contract_version":"1"}"#).await;
    assert_eq!(answered, StatusCode::UNAUTHORIZED, "{engine}: the disabled namesake's key is refused: {body}");
    let (answered, body) = send(&routes, OWNER, "POST", "/api/v1/agent/hello", r#"{"contract_version":"1"}"#).await;
    assert_eq!(answered, StatusCode::OK, "{engine}: the enabled agent's key still works: {body}");
    let claimable = scan(&db, None, Some(image), "pending", 0).await;
    let (answered, _) = send(&routes, TWIN, "GET", "/api/v1/agent/jobs?wait=0", "").await;
    assert_eq!(answered, StatusCode::UNAUTHORIZED, "{engine}: nor does it claim");
    assert_eq!(status(&db, claimable).await, "pending", "{engine}: the scan stays queued");

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

/// A database that cannot be reached, behind a key the chain accepts: the lookup of the agent fails.
#[tokio::test]
async fn an_unreadable_database_is_not_the_agents_fault() {
    let db = support::unreachable();
    let routes = router(&db, compose(&db, system_clock()));
    let (answered, body) = send(&routes, OWNER, "POST", "/api/v1/agent/hello", r#"{"contract_version":"1"}"#).await;
    assert_eq!(answered, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert!(body["correlationId"].is_string(), "the 500 quotes its reference: {body}");
}
