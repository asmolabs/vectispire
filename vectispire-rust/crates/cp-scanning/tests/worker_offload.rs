//! Tests for the built-in worker offloading rounds — `ScanWorkerOffloadTest`'s port.
//!
//! A round executes the scans it claims in this process. `tick()` submits the round to an asynchronous
//! background task and returns immediately, so that the maintenance scheduler is never blocked by a long
//! running scan.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use tokio::sync::Notify;
use uuid::Uuid;
use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
use vectispire_cp_db::Tx;
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_scanning::dispatcher::{DispatchQueue, DispatcherConfig, SastSwitch, ScanResult, TargetRows};
use vectispire_cp_scanning::ports::{BundledRules, NoPlugins, PortError};
use vectispire_cp_scanning::views::ScanView;
use vectispire_cp_scanning::{
    Abandoned, AgentClaim, Exclusion, Reclaimed, ScanDispatcher, ScanWorker, WorkerProperties,
};
use vectispire_cp_targets::credentials::{StoredGitToken, StoredSshKey};
use vectispire_cp_targets::views::{ContainerView, RepositoryView};
use vectispire_domain::FailureKind;
use vectispire_domain::git_host_allowlist::GitHostAllowlist;
use vectispire_domain::scan_queue::Next;
use vectispire_domain::secret::Secret;

fn dummy_scan() -> ScanView {
    ScanView {
        id: 42,
        branch: "main".to_owned(),
        sub_path: None,
        status: "scanning".to_owned(),
        duration_ms: None,
        findings_count: 0,
        new_issues_count: 0,
        resolved_issues_count: 0,
        error: None,
        created_at: OffsetDateTime::UNIX_EPOCH,
        version: None,
        project_type: None,
        repo_id: None,
        container_id: Some(10),
        required_agent_label: None,
        claimed_by: None,
        claimed_at: None,
        lease_expires_at: None,
        attempts: 1,
        not_before: None,
        plugin_steps: None,
        examined_types: None,
        detected_languages: None,
        sast_languages: None,
        has_sbom: false,
    }
}

#[derive(Default)]
struct DummyQueue;

impl DispatchQueue for DummyQueue {
    fn count_held<'a>(&'a self, _worker: &'a str) -> BoxFuture<'a, Result<i64, PortError>> {
        Box::pin(async { Ok(0) })
    }

    fn claim<'a>(
        &'a self,
        _room: i64,
        _worker: &'a str,
        _labels: &'a [String],
    ) -> BoxFuture<'a, Result<Vec<ScanView>, PortError>> {
        Box::pin(async { Ok(vec![dummy_scan()]) })
    }

    fn claim_within<'a>(
        &'a self,
        _agent: Uuid,
        _limit: i64,
        _labels: &'a [String],
        _exclusion: &'a dyn Exclusion,
    ) -> BoxFuture<'a, Result<AgentClaim, PortError>> {
        unreachable!()
    }

    fn by_id(&self, _id: i64) -> BoxFuture<'_, Result<Option<ScanView>, PortError>> {
        unreachable!()
    }

    fn renew_lease<'a>(&'a self, _scan_id: i64, _worker: &'a str) -> BoxFuture<'a, Result<bool, PortError>> {
        Box::pin(async { Ok(true) })
    }

    fn requeue<'a>(&'a self, _scan_id: i64, _worker: &'a str) -> BoxFuture<'a, Result<bool, PortError>> {
        Box::pin(async { Ok(true) })
    }

    fn requeue_refunded<'a>(&'a self, _scan_id: i64, _worker: &'a str) -> BoxFuture<'a, Result<bool, PortError>> {
        Box::pin(async { Ok(true) })
    }

    fn abandon<'a>(
        &'a self,
        _id: i64,
        _worker: &'a str,
        attempt: i32,
        _kind: FailureKind,
        _reason: &'a (dyn Fn(&Abandoned) -> String + Send + Sync),
    ) -> BoxFuture<'a, Result<Option<Abandoned>, PortError>> {
        Box::pin(async move { Ok(Some(Abandoned { next: Next::Fail { permanent: true }, attempt, max_attempts: 3 })) })
    }

    fn reclaim_lapsed_leases(&self) -> BoxFuture<'_, Result<Reclaimed, PortError>> {
        Box::pin(async { Ok(Reclaimed { requeued: vec![], failed: vec![] }) })
    }

    fn record_sast_languages<'a>(&'a self, _id: i64, _column: Option<&'a str>) -> BoxFuture<'a, Result<(), PortError>> {
        Box::pin(async { Ok(()) })
    }

    fn lease(&self) -> Duration {
        Duration::from_secs(1200)
    }

    fn hold_for_write<'a>(
        &'a self,
        _tx: &'a mut Tx,
        _id: i64,
        _worker: &'a str,
    ) -> BoxFuture<'a, Result<bool, PortError>> {
        unreachable!()
    }

    fn by_id_in<'a>(&'a self, _tx: &'a mut Tx, _id: i64) -> BoxFuture<'a, Result<Option<ScanView>, PortError>> {
        unreachable!()
    }

    fn write_result<'a>(&'a self, _tx: &'a mut Tx, _result: &'a ScanResult) -> BoxFuture<'a, Result<(), PortError>> {
        unreachable!()
    }

    fn begin(&self) -> BoxFuture<'_, Result<Tx, PortError>> {
        unreachable!()
    }
}

#[derive(Default)]
struct DummyTargets;

impl TargetRows for DummyTargets {
    fn repository(&self, _id: i64) -> BoxFuture<'_, Result<Option<RepositoryView>, PortError>> {
        Box::pin(async { Ok(None) })
    }

    fn container(&self, id: i64) -> BoxFuture<'_, Result<Option<ContainerView>, PortError>> {
        Box::pin(async move {
            Ok(Some(ContainerView {
                id,
                image_name: "test-container".to_owned(),
                tag: "latest".to_owned(),
                registry: None,
                scan_interval_minutes: None,
                scan_cron: None,
                scan_manual_only: false,
                required_agent_label: None,
                last_scheduled_scan_at: None,
                tier: "standard".to_owned(),
                in_certified_scope: false,
                project_id: None,
            }))
        })
    }

    fn carrying_credentials<'a>(&'a self, _ids: &'a BTreeSet<i64>) -> BoxFuture<'a, Result<BTreeSet<i64>, PortError>> {
        Box::pin(async { Ok(BTreeSet::new()) })
    }

    fn git_token(&self, _id: Uuid) -> BoxFuture<'_, Result<Option<StoredGitToken>, PortError>> {
        Box::pin(async { Ok(None) })
    }

    fn ssh_key(&self, _id: Uuid) -> BoxFuture<'_, Result<Option<StoredSshKey>, PortError>> {
        Box::pin(async { Ok(None) })
    }
}

struct Switch(bool);
impl SastSwitch for Switch {
    fn sast_enabled(&self) -> BoxFuture<'_, Result<bool, PortError>> {
        Box::pin(async { Ok(self.0) })
    }
}

#[derive(Default)]
struct DummyAudit;
impl vectispire_cp_targets::AuditSink for DummyAudit {
    fn record(&self, _record: vectispire_cp_audit::Record) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

/// A controllable runner that allows testing async offloading and concurrency boundaries.
struct ControllableRunner {
    dispatch_started: Arc<Notify>,
    release_dispatch: Arc<Notify>,
    call_count: Arc<AtomicUsize>,
}

impl vectispire_cp_scanning::ports::ScanRunner for ControllableRunner {
    fn run<'a>(
        &'a self,
        _task: &'a vectispire_protocol::ScanTask,
    ) -> BoxFuture<'a, Result<vectispire_protocol::Received<'static>, vectispire_cp_scanning::ports::RunFailure>> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let started = self.dispatch_started.clone();
        let release = self.release_dispatch.clone();
        Box::pin(async move {
            started.notify_one();
            release.notified().await;
            Err(vectispire_cp_scanning::ports::RunFailure {
                message: "controlled test run".to_owned(),
                kind: FailureKind::Permanent,
            })
        })
    }
}

fn test_dispatcher(runner: Arc<dyn vectispire_cp_scanning::ports::ScanRunner>) -> Arc<ScanDispatcher> {
    let key = "cmVmZXJlbmNlLXNjYW5uaW5nLWtleS0zMi1ieXRlcyE=";
    let config = EncryptionConfig { key: Some(Secret::new(key)), ..Default::default() };
    let door = VaultDoor {
        sender: vectispire_cp_outbound::PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: vectispire_cp_outbound::OutboundUrlGuard::new(Vec::new()),
    };
    let encryption = Arc::new(Encryption::new(&config, door).unwrap());
    Arc::new(ScanDispatcher::new(DispatcherConfig {
        queue: Arc::new(DummyQueue),
        targets: Arc::new(DummyTargets),
        encryption,
        sast: Arc::new(Switch(false)),
        rule_sets: Arc::new(BundledRules),
        plugins: Arc::new(NoPlugins),
        ingestor: Arc::new(vectispire_cp_scanning::ports::IngestionStandIn::default()),
        audit: Arc::new(DummyAudit),
        allowed_hosts: GitHostAllowlist::parse(None).unwrap(),
        image_platform: None,
        runner: Some(runner),
        scanned: Vec::new(),
    }))
}

#[tokio::test]
async fn tick_returns_while_the_round_is_still_running() {
    let dispatch_started = Arc::new(Notify::new());
    let release_dispatch = Arc::new(Notify::new());
    let call_count = Arc::new(AtomicUsize::new(0));

    let runner = Arc::new(ControllableRunner {
        dispatch_started: dispatch_started.clone(),
        release_dispatch: release_dispatch.clone(),
        call_count: call_count.clone(),
    });

    let dispatcher = test_dispatcher(runner);
    let worker =
        ScanWorker::new(dispatcher, WorkerProperties { enabled: true, max_concurrent: 2, labels: String::new() });

    let before = Instant::now();
    let accepted = worker.tick();
    let took = before.elapsed();

    assert!(accepted, "first tick must be accepted");
    assert!(took < Duration::from_secs(2), "tick must not wait for the round it submitted, took {took:?}");

    // The round must actually start in the background task
    tokio::time::timeout(Duration::from_secs(5), dispatch_started.notified())
        .await
        .expect("round must start within 5 seconds");

    assert_eq!(call_count.load(Ordering::SeqCst), 1);
    assert!(worker.is_busy(), "worker must be busy while round is running");

    // The guard still means what it meant: a tick arriving mid-round is skipped
    assert!(!worker.tick(), "subsequent tick while busy must be skipped");
    assert!(!worker.tick(), "subsequent tick while busy must be skipped");

    // Let the round finish
    release_dispatch.notify_one();

    // Give background task a moment to finish and clear busy flag
    for _ in 0..50 {
        if !worker.is_busy() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!worker.is_busy(), "busy flag must be cleared after round finishes");
}

#[tokio::test]
async fn accepts_the_next_round_once_the_previous_one_has_finished() {
    let dispatch_started = Arc::new(Notify::new());
    let release_dispatch = Arc::new(Notify::new());
    let call_count = Arc::new(AtomicUsize::new(0));

    let runner = Arc::new(ControllableRunner {
        dispatch_started: dispatch_started.clone(),
        release_dispatch: release_dispatch.clone(),
        call_count: call_count.clone(),
    });

    let dispatcher = test_dispatcher(runner);
    let worker =
        ScanWorker::new(dispatcher, WorkerProperties { enabled: true, max_concurrent: 2, labels: String::new() });

    // First round
    assert!(worker.tick());
    tokio::time::timeout(Duration::from_secs(5), dispatch_started.notified()).await.expect("first round must start");

    // Complete the first round
    release_dispatch.notify_one();
    for _ in 0..50 {
        if !worker.is_busy() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!worker.is_busy());

    // Second round is accepted
    assert!(worker.tick(), "tick after first round completes must be accepted");
    tokio::time::timeout(Duration::from_secs(5), dispatch_started.notified()).await.expect("second round must start");

    assert_eq!(call_count.load(Ordering::SeqCst), 2);
    release_dispatch.notify_one();
}

#[tokio::test]
async fn disabled_worker_does_not_tick() {
    let runner = Arc::new(ControllableRunner {
        dispatch_started: Arc::new(Notify::new()),
        release_dispatch: Arc::new(Notify::new()),
        call_count: Arc::new(AtomicUsize::new(0)),
    });
    let dispatcher = test_dispatcher(runner);
    let worker =
        ScanWorker::new(dispatcher, WorkerProperties { enabled: false, max_concurrent: 2, labels: String::new() });

    assert!(!worker.tick(), "disabled worker tick must return false");
    assert!(!worker.is_busy(), "disabled worker must never become busy");
}
