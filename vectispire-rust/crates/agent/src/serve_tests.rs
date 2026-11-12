//! The loop against a stub control plane — `AgentLoopTest` and `AgentLoopConcurrencyTest` of the Java
//! agent, ported. The runner is the test's: these are the loop's decisions, not a scan's.

use super::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::atomic::AtomicU32;
use vectispire_crypto::SealingKeyPair;
use vectispire_protocol::Findings;
use vectispire_testkit::control_plane::{Request, Response, StubControlPlane};
use vectispire_tls::TlsTrust;

fn sealing() -> SealingKeyPair {
    SealingKeyPair::from_secret_bytes(Sha256::digest(b"vectispire-rust-reference:rust-sealing-key").into())
}

/// The Java side's envelope of an HTTPS token for `gitlab.example.org`, and its clear text.
fn sealed_token() -> (String, String) {
    let vectors = vectispire_testkit::read_json("crypto/java-vectors.json");
    let envelope = vectors["envelopes_to_rust"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["context"] == "https-token:18:gitlab.example.org;14:x-access-token;")
        .unwrap()
        .clone();
    (envelope["sealed"].as_str().unwrap().to_owned(), envelope["plain"].as_str().unwrap().to_owned())
}

fn task(scan: i64, token: Option<&str>) -> Value {
    let https = token.map_or(
        Value::Null,
        |token| json!({"host": "gitlab.example.org", "username": "x-access-token", "token": token}),
    );
    json!({"scanId": scan, "attempt": 1, "task": {"target": {"kind": "repository",
        "url": "https://gitlab.example.org/g/p.git", "branch": "main", "https": https}, "steps": ["SECRETS"]}})
}

fn settings(heartbeat: Duration) -> Settings {
    Settings {
        claim_wait: Duration::from_secs(1),
        retry_delay: Duration::from_millis(10),
        heartbeat,
        secrets: vec![Secret::new("invented-signing-seed-value")],
    }
}

fn client(stub: &StubControlPlane) -> Arc<AgentClient> {
    Arc::new(
        AgentClient::new(stub.url(), Secret::new("invented-api-key"), &TlsTrust::BuiltIn, None, sealing(), 1).unwrap(),
    )
}

/// A runner that answers each scan with the function's answer, after `delay`.
struct Scripted<F> {
    answer: F,
    delay: Duration,
    seen: Mutex<Vec<ScanTask>>,
}

impl<F: Fn(&ScanTask) -> Result<ScanArtifacts, ExecutionFailure> + Send + Sync + 'static> Execute for Scripted<F> {
    fn execute(&self, task: ScanTask) -> impl Future<Output = Result<ScanArtifacts, ExecutionFailure>> + Send {
        let answer = (self.answer)(&task);
        self.seen.lock().unwrap().push(task);
        let delay = self.delay;
        async move {
            tokio::time::sleep(delay).await;
            answer
        }
    }
}

fn scripted<F>(answer: F, delay: Duration) -> Arc<Scripted<F>> {
    Arc::new(Scripted { answer, delay, seen: Mutex::new(Vec::new()) })
}

fn found_nothing(_: &ScanTask) -> Result<ScanArtifacts, ExecutionFailure> {
    Ok(ScanArtifacts { secrets: Some(Findings::default()), ..ScanArtifacts::default() })
}

fn one_loop<F: Fn(&ScanTask) -> Result<ScanArtifacts, ExecutionFailure> + Send + Sync + 'static>(
    stub: &StubControlPlane,
    answer: F,
    heartbeat: Duration,
    delay: Duration,
) -> Arc<AgentLoop<Scripted<F>>> {
    Arc::new(AgentLoop::new(client(stub), scripted(answer, delay), settings(heartbeat), 1))
}

#[tokio::test]
async fn an_empty_queue_does_nothing() {
    let stub = StubControlPlane::answering(vec![Response::status(204)]);
    let outcome = one_loop(&stub, found_nothing, Duration::from_secs(60), Duration::ZERO).run_once().await.unwrap();
    assert_eq!(outcome, Outcome::default());
    assert_eq!(stub.routes(), ["GET /api/v1/agent/jobs"]);
}

#[tokio::test]
async fn a_claimed_scan_is_run_and_submitted() {
    let stub = StubControlPlane::answering(vec![Response::json(200, task(7, None)), Response::status(200)]);
    let outcome = one_loop(&stub, found_nothing, Duration::from_secs(60), Duration::ZERO).run_once().await.unwrap();
    assert_eq!(outcome, Outcome::COMPLETED);
    assert_eq!(stub.routes(), ["GET /api/v1/agent/jobs", "POST /api/v1/agent/jobs/7/result"]);
    assert_eq!(stub.requests()[1].json()["secrets"], json!([]), "found nothing is a list, empty");
}

#[tokio::test]
async fn a_failed_run_hands_back_nothing_and_reports_its_reason_scrubbed_of_every_secret_held() {
    let (sealed, plain) = sealed_token();
    let leaked = format!(
        "clone of https://x-access-token:{plain}@gitlab.example.org failed; api key invented-api-key; seed \
         invented-signing-seed-value"
    );
    let stub = StubControlPlane::answering(vec![
        Response::json(200, task(9, Some(&sealed))),
        Response::json(200, json!({"retried": true})),
    ]);
    let failing = move |_: &ScanTask| Err(ExecutionFailure { message: leaked.clone(), kind: FailureKind::Transient });
    let outcome = one_loop(&stub, failing, Duration::from_secs(60), Duration::ZERO).run_once().await.unwrap();
    assert_eq!(outcome, Outcome::FAILED);
    assert_eq!(stub.routes(), ["GET /api/v1/agent/jobs", "POST /api/v1/agent/jobs/9/failure"], "no result at all");
    let report = stub.requests()[1].json();
    let reason = report["reason"].as_str().unwrap();
    for secret in [plain.as_str(), "invented-api-key", "invented-signing-seed-value"] {
        assert!(!reason.contains(secret), "{secret} left in {reason:?}");
    }
    assert_eq!(report["kind"], "TRANSIENT");
}

#[tokio::test]
async fn a_permanent_failure_is_reported_as_one() {
    let stub = StubControlPlane::answering(vec![Response::json(200, task(3, None)), Response::json(200, json!({}))]);
    let failing =
        |_: &ScanTask| Err(ExecutionFailure { message: "branch absent".into(), kind: FailureKind::Permanent });
    one_loop(&stub, failing, Duration::from_secs(60), Duration::ZERO).run_once().await.unwrap();
    assert_eq!(stub.requests()[1].json()["kind"], "PERMANENT");
}

#[tokio::test]
async fn an_unreported_failure_falls_back_to_the_lease_and_still_costs_nothing_else() {
    for report in [Response::status(404), Response::status(500)] {
        let stub = StubControlPlane::answering(vec![Response::json(200, task(4, None)), report]);
        let failing = |_: &ScanTask| Err(ExecutionFailure { message: "x".into(), kind: FailureKind::Transient });
        let outcome = one_loop(&stub, failing, Duration::from_secs(60), Duration::ZERO).run_once().await.unwrap();
        assert_eq!(outcome, Outcome::FAILED);
    }
}

#[tokio::test]
async fn a_claimed_task_that_cannot_be_used_is_reported_as_permanent_and_costs_a_turn_not_the_agent() {
    let stub = StubControlPlane::answering(vec![
        Response::json(200, task(5, Some("invented-clear-token-value"))),
        Response::json(200, json!({"retried": false})),
    ]);
    let runner = scripted(found_nothing, Duration::ZERO);
    let looping = AgentLoop::new(client(&stub), runner.clone(), settings(Duration::from_secs(60)), 1);
    assert_eq!(looping.run_once().await.unwrap(), Outcome::default());
    assert!(runner.seen.lock().unwrap().is_empty(), "never run");
    assert_eq!(stub.routes(), ["GET /api/v1/agent/jobs", "POST /api/v1/agent/jobs/5/failure"]);
    let report = stub.requests()[1].json();
    assert_eq!(report["kind"], "PERMANENT");
    assert!(report["reason"].as_str().unwrap().starts_with("A HTTPS token arrived unsealed"));
    assert!(!report["reason"].as_str().unwrap().contains("invented-clear-token"));
}

#[tokio::test]
async fn a_failed_claim_costs_a_turn_and_a_refused_key_stops_the_agent() {
    let stub = StubControlPlane::answering(vec![Response::status(500), Response::status(401)]);
    let looping = one_loop(&stub, found_nothing, Duration::from_secs(60), Duration::ZERO);
    assert_eq!(looping.run_once().await.unwrap(), Outcome::default());
    let refused = looping.run_once().await.unwrap_err();
    assert!(matches!(refused, ProtocolError::Unauthorized(_)));
    let stub = StubControlPlane::answering(vec![Response::json(409, json!({"detail": "Contract 2."}))]);
    // A contract gap is the hello's to say; on a claim a 409 is one more failed claim.
    let retried = one_loop(&stub, found_nothing, Duration::from_secs(60), Duration::ZERO);
    assert_eq!(retried.run_once().await.unwrap(), Outcome::default());
    let stub = StubControlPlane::start(|_: &Request| Response::status(401));
    let fatal = one_loop(&stub, found_nothing, Duration::from_secs(60), Duration::ZERO);
    let stopped = tokio::time::timeout(Duration::from_secs(5), fatal.serve()).await.unwrap();
    assert!(matches!(stopped, Err(ProtocolError::Unauthorized(_))), "serve stops on a refused key: {stopped:?}");
    assert_eq!(stub.requests().len(), 1, "and does not retry it");
}

#[tokio::test]
async fn a_lease_taken_over_during_the_run_discards_the_result() {
    let stub = StubControlPlane::start(|request: &Request| match request.route().as_str() {
        "GET /api/v1/agent/jobs" => Response::json(200, task(6, None)),
        "POST /api/v1/agent/jobs/6/heartbeat" => Response::status(409),
        _ => Response::status(500),
    });
    let looping = one_loop(&stub, found_nothing, Duration::from_millis(20), Duration::from_millis(300));
    assert_eq!(looping.run_once().await.unwrap(), Outcome::ABANDONED);
    assert!(stub.routes().iter().any(|route| route == "POST /api/v1/agent/jobs/6/heartbeat"));
    assert!(!stub.routes().iter().any(|route| route.ends_with("/result")), "the successor's result stands");
}

#[tokio::test]
async fn a_missed_heartbeat_is_not_a_lost_lease() {
    let stub = StubControlPlane::start(|request: &Request| match request.route().as_str() {
        "GET /api/v1/agent/jobs" => Response::json(200, task(8, None)),
        "POST /api/v1/agent/jobs/8/heartbeat" => Response::status(503),
        _ => Response::status(200),
    });
    let looping = one_loop(&stub, found_nothing, Duration::from_millis(20), Duration::from_millis(200));
    assert_eq!(looping.run_once().await.unwrap(), Outcome::COMPLETED);
}

#[tokio::test]
async fn work_done_but_not_delivered_counts_as_failed_and_is_not_retried_here() {
    let stub = StubControlPlane::answering(vec![Response::json(200, task(2, None)), Response::status(500)]);
    let outcome = one_loop(&stub, found_nothing, Duration::from_secs(60), Duration::ZERO).run_once().await.unwrap();
    assert_eq!(outcome, Outcome::FAILED);
    assert_eq!(stub.routes().iter().filter(|route| route.ends_with("/result")).count(), 1);
}

// ------------------------------------------------------------------------------- several at once

/// A control plane with `queued` scans, answering an empty poll after a short wait, and a header
/// saying `limit` when one is set.
fn queue(queued: Vec<i64>, limit: Arc<Mutex<Option<u32>>>) -> StubControlPlane {
    let queued = Mutex::new(VecDeque::from(queued));
    StubControlPlane::start(move |request: &Request| {
        let header = |response: Response| match *limit.lock().unwrap() {
            Some(limit) => response.with_header("X-Vectispire-Max-Concurrent", limit.to_string()),
            None => response,
        };
        match request.route().as_str() {
            "GET /api/v1/agent/jobs" => match queued.lock().unwrap().pop_front() {
                Some(scan) => header(Response::json(200, task(scan, None))),
                None => {
                    std::thread::sleep(Duration::from_millis(30));
                    header(Response::status(204))
                }
            },
            _ => Response::status(200),
        }
    })
}

/// A runner whose scans wait until released, counting those running.
struct Held {
    running: AtomicU32,
    most: AtomicU32,
    release: Notify,
    released: AtomicBool,
}

impl Execute for Held {
    fn execute(&self, _task: ScanTask) -> impl Future<Output = Result<ScanArtifacts, ExecutionFailure>> + Send {
        let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.most.fetch_max(now, Ordering::SeqCst);
        async move {
            while !self.released.load(Ordering::SeqCst) {
                let released = self.release.notified();
                tokio::pin!(released);
                released.as_mut().enable();
                if self.released.load(Ordering::SeqCst) {
                    break;
                }
                released.await;
            }
            self.running.fetch_sub(1, Ordering::SeqCst);
            found_nothing(&_task)
        }
    }
}

fn held() -> Arc<Held> {
    Arc::new(Held {
        running: AtomicU32::new(0),
        most: AtomicU32::new(0),
        release: Notify::new(),
        released: AtomicBool::new(false),
    })
}

impl Held {
    fn let_go(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.release.notify_waiters();
    }
}

async fn eventually(condition: impl Fn() -> bool) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the condition never held");
}

#[tokio::test]
async fn runs_its_limit_in_parallel_and_does_not_even_ask_for_one_more_then_stops_after_handing_back() {
    let limit = Arc::new(Mutex::new(None));
    let stub = queue(vec![1, 2, 3, 4], limit);
    let runner = held();
    let looping = Arc::new(AgentLoop::new(client(&stub), runner.clone(), settings(Duration::from_secs(60)), 2));
    let serving = tokio::spawn({
        let looping = looping.clone();
        async move { looping.serve().await }
    });
    eventually(|| runner.running.load(Ordering::SeqCst) == 2).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let claims = stub.routes().iter().filter(|route| *route == "GET /api/v1/agent/jobs").count();
    assert_eq!(claims, 2, "a full agent does not poll");
    assert_eq!(looping.slots().busy(), 2);

    looping.stop();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!serving.is_finished(), "a stop waits for the running scans");
    runner.let_go();
    tokio::time::timeout(Duration::from_secs(5), serving).await.unwrap().unwrap().unwrap();
    let results = stub.routes().iter().filter(|route| route.ends_with("/result")).count();
    assert_eq!(results, 2, "both running scans were handed back, and nothing more was claimed");
    assert_eq!(runner.most.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_limit_raised_on_a_claim_s_answer_is_used_on_the_next_one() {
    let limit = Arc::new(Mutex::new(Some(3)));
    let stub = queue(vec![1, 2, 3, 4], limit.clone());
    let runner = held();
    let looping = Arc::new(AgentLoop::new(client(&stub), runner.clone(), settings(Duration::from_secs(60)), 1));
    let serving = tokio::spawn({
        let looping = looping.clone();
        async move { looping.serve().await }
    });
    eventually(|| runner.running.load(Ordering::SeqCst) == 3).await;
    assert_eq!(looping.slots().limit(), 3);
    looping.stop();
    runner.let_go();
    tokio::time::timeout(Duration::from_secs(5), serving).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn a_finished_scan_frees_its_slot() {
    let stub = queue(vec![1, 2, 3], Arc::new(Mutex::new(None)));
    let looping = Arc::new(AgentLoop::new(
        client(&stub),
        scripted(found_nothing, Duration::from_millis(30)),
        settings(Duration::from_secs(60)),
        1,
    ));
    let serving = tokio::spawn({
        let looping = looping.clone();
        async move { looping.serve().await }
    });
    eventually(|| stub.routes().iter().filter(|route| route.ends_with("/result")).count() == 3).await;
    looping.stop();
    tokio::time::timeout(Duration::from_secs(5), serving).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn a_stop_cuts_the_retry_pause_short() {
    let stub = StubControlPlane::start(|_: &Request| Response::status(500));
    let mut patient = settings(Duration::from_secs(60));
    patient.retry_delay = Duration::from_secs(300);
    let looping = Arc::new(AgentLoop::new(client(&stub), scripted(found_nothing, Duration::ZERO), patient, 1));
    let serving = tokio::spawn({
        let looping = looping.clone();
        async move { looping.serve().await }
    });
    eventually(|| !stub.requests().is_empty()).await;
    looping.stop();
    tokio::time::timeout(Duration::from_secs(5), serving).await.unwrap().unwrap().unwrap();
}

#[test]
fn a_slot_limit_is_held_within_its_bounds() {
    assert_eq!(Slots::new(0).limit(), 1);
    assert_eq!(Slots::new(99).limit(), 16);
    let slots = Slots::new(2);
    slots.resize(0);
    assert_eq!(slots.limit(), 1);
}
