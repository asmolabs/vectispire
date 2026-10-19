//! The built-in worker: runs inside Vectispire's process and drains the queue — Task 2.10.
//!
//! **It has no privilege**: it claims exactly as a remote agent would, with the same lease and ownership
//! checks. What makes adding a remote agent require no change here is that the queue does not know who
//! serves it.
//!
//! **One turn at a time**: without the busy guard, a slow scan would let turns stack up, all claiming in
//! parallel and overshooting the concurrency limit computed before the round started.
//!
//! **Submits the round; does not run it**: `tick()` offloads execution to an asynchronous background task
//! and returns immediately (`ScanWorkerOffloadTest`), keeping the maintenance and scheduling loops unblocked.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use uuid::Uuid;
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_domain::FailureKind;
use vectispire_protocol::{Received, ScanArtifacts, ScanTask};
use vectispire_runner::{Images, Places, RuleProvider, Runner};
use vectispire_tls::TlsTrust;

use crate::dispatcher::{Dispatched, ScanDispatcher};
use crate::ports::{PortError, RunFailure, ScanRuleSets, ScanRunner};

/// Configuration for the built-in worker.
#[derive(Debug, Clone)]
pub struct WorkerProperties {
    pub enabled: bool,
    pub max_concurrent: i32,
    pub labels: String,
}

impl Default for WorkerProperties {
    fn default() -> Self {
        Self { enabled: true, max_concurrent: 2, labels: String::new() }
    }
}

/// The built-in worker: claims scans and executes them using the shared `vectispire-runner` pipeline.
pub struct ScanWorker {
    dispatcher: Arc<ScanDispatcher>,
    properties: WorkerProperties,
    worker: String,
    busy: Arc<AtomicBool>,
}

impl std::fmt::Debug for ScanWorker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScanWorker")
            .field("worker", &self.worker)
            .field("properties", &self.properties)
            .field("busy", &self.is_busy())
            .finish()
    }
}

impl ScanWorker {
    /// Creates a new built-in worker with a unique identity for this process instance.
    pub fn new(dispatcher: Arc<ScanDispatcher>, properties: WorkerProperties) -> Self {
        let suffix: String = Uuid::new_v4().to_string().chars().take(8).collect();
        let worker = format!("{}/{suffix}", host_name());
        Self { dispatcher, properties, worker, busy: Arc::new(AtomicBool::new(false)) }
    }

    /// Creates a worker with an explicit claimant identity (used in deterministic tests).
    pub fn with_identity(dispatcher: Arc<ScanDispatcher>, properties: WorkerProperties, identity: String) -> Self {
        Self { dispatcher, properties, worker: identity, busy: Arc::new(AtomicBool::new(false)) }
    }

    /// What this worker calls itself on claims and in logs (`claimedBy`).
    pub fn identity(&self) -> &str {
        &self.worker
    }

    /// Worker configuration properties.
    pub fn properties(&self) -> &WorkerProperties {
        &self.properties
    }

    /// Whether a dispatch round is currently executing.
    pub fn is_busy(&self) -> bool {
        self.busy.load(Ordering::Acquire)
    }

    /// Submits a dispatch round to the background runtime if enabled and not already busy.
    ///
    /// Returns `true` if a new round was accepted and submitted, or `false` if skipped.
    /// Does not block: returns immediately while the round executes in the background.
    pub fn tick(&self) -> bool {
        if !self.properties.enabled {
            return false;
        }
        if self.busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return false;
        }

        let dispatcher = self.dispatcher.clone();
        let worker = self.worker.clone();
        let properties = self.properties.clone();
        let busy = self.busy.clone();

        tokio::spawn(async move {
            let _guard = BusyGuard(busy);
            let labels = vectispire_domain::agent_labels::parse(Some(&properties.labels));
            match dispatcher.dispatch(&worker, properties.max_concurrent, &labels).await {
                Ok(result) => {
                    if result.claimed > 0 {
                        tracing::info!(
                            claimed = result.claimed,
                            completed = result.completed,
                            failed = result.failed,
                            "{} scan(s) claimed — {} completed, {} failed.",
                            result.claimed,
                            result.completed,
                            result.failed
                        );
                    }
                }
                Err(error) => {
                    tracing::error!(%error, "The dispatch round failed.");
                }
            }
        });

        true
    }

    /// Runs one dispatch round directly and awaits completion (used in synchronous testing and composition).
    pub async fn round(&self) -> Result<Dispatched, PortError> {
        let labels = vectispire_domain::agent_labels::parse(Some(&self.properties.labels));
        self.dispatcher.dispatch(&self.worker, self.properties.max_concurrent, &labels).await
    }
}

/// RAII guard ensuring the `busy` atomic flag is reset upon round completion or cancellation.
struct BusyGuard(Arc<AtomicBool>);

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Adapter connecting the control plane's `ScanRuleSets` to the runner's `RuleProvider`.
struct ControlPlaneRuleProvider(Arc<dyn ScanRuleSets>);

impl RuleProvider for ControlPlaneRuleProvider {
    fn fetch_rule_set<'a>(
        &'a self,
        hash: &'a str,
    ) -> vectispire_runner::BoxFuture<'a, Result<Vec<vectispire_runner::StoredFile>, String>> {
        let rule_sets = self.0.clone();
        Box::pin(async move {
            let files = rule_sets.files_of(hash).await.map_err(|error| error.to_string())?;
            Ok(files
                .into_iter()
                .map(|f| vectispire_runner::StoredFile {
                    path: f.path,
                    original_name: f.original_name.unwrap_or_default(),
                    content: f.content,
                })
                .collect())
        })
    }
}

/// The built-in worker's runner: adapts `vectispire-runner` to the control plane's `ScanRunner` port.
pub struct BuiltInScanRunner {
    runner: Arc<Runner>,
}

impl std::fmt::Debug for BuiltInScanRunner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("BuiltInScanRunner").field("runner", &self.runner).finish()
    }
}

impl BuiltInScanRunner {
    /// Constructs a runner using the provided rule sets, images, paths, and TLS trust.
    pub fn new(
        rule_sets: Arc<dyn ScanRuleSets>,
        images: Images,
        places: Places,
        vulnerability_root: Option<PathBuf>,
        trust: TlsTrust,
    ) -> Result<Self, String> {
        let provider = Arc::new(ControlPlaneRuleProvider(rule_sets));
        let runner = Arc::new(Runner::new(Some(provider), images, places, vulnerability_root, trust)?);
        Ok(Self { runner })
    }

    /// Wraps an existing `Runner`.
    pub fn from_runner(runner: Arc<Runner>) -> Self {
        Self { runner }
    }
}

impl ScanRunner for BuiltInScanRunner {
    fn run<'a>(&'a self, task: &'a ScanTask) -> BoxFuture<'a, Result<Received<'static>, RunFailure>> {
        let runner = self.runner.clone();
        let task = task.clone();
        Box::pin(async move {
            let artifacts =
                runner.run(task).await.map_err(|error| RunFailure { message: error.message, kind: error.kind })?;
            let body = artifacts.to_body().map_err(|error| RunFailure {
                message: format!("Scan artifacts serialization failed: {error}"),
                kind: FailureKind::Permanent,
            })?;
            let received = ScanArtifacts::read(body.as_bytes()).map_err(|error| RunFailure {
                message: format!("Scan artifacts unreadable: {error}"),
                kind: FailureKind::Permanent,
            })?;
            Ok(received.into_owned())
        })
    }
}

fn host_name() -> String {
    std::env::var("HOSTNAME").or_else(|_| std::env::var("HOST")).unwrap_or_else(|_| "unknown-host".to_owned())
}
