//! The agent protocol's answers that decide what an agent does next, through the routes, on both engines:
//!
//! - **a failure of this side is a 500, a refusal a 409.** Every dispatcher error was answered "this scan is no longer
//!   yours", which tells the agent to drop its result; Java's exception answers 500 and the agent sends it again.
//! - **a claim the agent never received goes back to the queue.** Java's `returnUndelivered`, on the delivery receipt
//!   `DeferredResult.setResult` returns; the Rust poller had none, and the scan sat claimed until its lease lapsed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use vectispire_cp_db::{Db, Engine};
use vectispire_cp_http::credentials::{BoxFuture, StaticCredentials};
use vectispire_cp_http::principal::Principal;
use vectispire_cp_scanning::ports::{IngestError, Prepared, Reconciliation, ScanIngestor};
use vectispire_cp_scanning::views::ScanView;
use vectispire_protocol::Received;

use support::{
    Composed, Migrated, agent, clean, compose, compose_with_ingestor, container, scan, status, system_clock,
};

const TOKEN: &str = "agent-protocol-test-token"; // gitleaks:allow — a test fixture

/// An ingestion that refuses every result, as a database outage or a refused result does.
struct Refusing;

impl ScanIngestor for Refusing {
    fn prepare<'a>(&'a self, _scan: &'a ScanView, _artifacts: &'a Received<'_>) -> BoxFuture<'a, Prepared> {
        Box::pin(async { Arc::new(()) as Prepared })
    }

    fn ingest<'a>(
        &'a self,
        _tx: &'a mut vectispire_cp_db::Tx,
        _scan: &'a ScanView,
        _artifacts: &'a Received<'_>,
        _prepared: Prepared,
    ) -> BoxFuture<'a, Result<Reconciliation, IngestError>> {
        Box::pin(async { Err(IngestError::Failed("the ingestion failed".into())) })
    }
}

fn router(db: &Db, composed: Composed, name: &str) -> axum::Router {
    support::router(
        db,
        composed.targets,
        composed.scanning,
        composed.agents,
        StaticCredentials::default().key(TOKEN, Principal::agent(name)),
        "everyone",
    )
}

fn request(method: &str, uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("X-API-Key", TOKEN)
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

/// What the claim answered, read to the end.
async fn claim(router: &axum::Router) -> (StatusCode, serde_json::Value) {
    let response = router.clone().oneshot(request("GET", "/api/v1/agent/jobs", "")).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, if bytes.is_empty() { serde_json::Value::Null } else { serde_json::from_slice(&bytes).unwrap() })
}

async fn status_becomes(db: &Db, scan: i64, expected: &str) -> String {
    for _ in 0..50 {
        let now = status(db, scan).await;
        if now == expected {
            return now;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    status(db, scan).await
}

async fn suite(engine: Engine) {
    let migrated = Migrated::start(engine).await;
    let db = migrated.connect().await;

    // ── a failure is a 500; a refusal stays a 409 ──
    clean(&db).await;
    agent(&db, "edge", "delegated").await;
    let image = container(&db, "img").await;
    let claimed = scan(&db, None, Some(image), "pending", 0).await;
    let refusing = router(&db, compose_with_ingestor(&db, system_clock(), Arc::new(Refusing)), "edge");
    let (answered, task) = claim(&refusing).await;
    assert_eq!(answered, StatusCode::OK, "{engine}: the claim");
    assert_eq!(task["scanId"], claimed, "{engine}: the claimed scan");

    let response =
        refusing.clone().oneshot(request("POST", &format!("/api/v1/agent/jobs/{claimed}/result"), "{}")).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR, "{engine}: a failed write is not the agent's");
    let problem: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(problem["correlationId"].is_string(), "{engine}: the 500 quotes its reference: {problem}");
    assert!(
        !problem.to_string().contains("the ingestion failed"),
        "{engine}: the failure's own text stays in the log: {problem}"
    );
    assert_eq!(status(&db, claimed).await, "scanning", "{engine}: the scan is still the agent's, to send again");

    let unclaimed = scan(&db, None, Some(image), "completed", 1).await;
    let response = refusing
        .clone()
        .oneshot(request("POST", &format!("/api/v1/agent/jobs/{unclaimed}/result"), "{}"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT, "{engine}: a scan that is not the agent's is still a 409");

    // ── a claim the agent never read goes back; one it read stays ──
    clean(&db).await;
    agent(&db, "edge", "delegated").await;
    let image = container(&db, "img").await;
    let plain = router(&db, compose(&db, system_clock()), "edge");

    let dropped = scan(&db, None, Some(image), "pending", 0).await;
    let response = plain.clone().oneshot(request("GET", "/api/v1/agent/jobs", "")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{engine}: the claim");
    assert_eq!(status(&db, dropped).await, "scanning", "{engine}: claimed while its answer is on its way");
    drop(response);
    assert_eq!(
        status_becomes(&db, dropped, "pending").await,
        "pending",
        "{engine}: an answer dropped unread gives the scan back"
    );

    let (answered, task) = claim(&plain).await;
    assert_eq!(answered, StatusCode::OK, "{engine}: the scan given back is claimed again");
    assert_eq!(task["scanId"], dropped);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(status(&db, dropped).await, "scanning", "{engine}: an answer read to the end keeps the claim");

    db.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_mysql() {
    suite(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_postgresql() {
    suite(Engine::PostgreSql).await;
}
