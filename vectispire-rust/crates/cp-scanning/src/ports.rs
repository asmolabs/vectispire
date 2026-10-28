//! What `scanning` asks of the modules above it, as ports it declares so that the dependency points from them to here
//! (decision 0029): the agent's row the claim locks (`agents`, 2.9), the uploaded rule sets (`rules`, Phase 3), the
//! plugins a repository runs (`plugins`, Phase 4), the ingestion of a result (2.8, in this crate but its own files), the
//! reactions to a completed scan (`checklists`, `compliance`, Phase 5), and the built-in worker's runner (2.10).
//!
//! Each has a stand-in here, named after what it stands for, which the binary composes until the owner lands:
//! [`AgentsStandIn`], [`BundledRules`], [`NoPlugins`], [`IngestionStandIn`]. A composition test lists them, so that
//! none survives cut-over unseen (`MaintenanceJobsTest`'s lesson: a missing caller is only visible there).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::Tx;
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_domain::FindingType;
use vectispire_protocol::{PluginRef, Received, ScanTask, StoredFile};

use crate::views::ScanView;

/// A port's failure — never read as an empty answer (decision 0007).
pub type PortError = Box<dyn std::error::Error + Send + Sync>;

/// `AgentClaimLock`: the claimant's own row, written first in the claim's transaction, so that two claims by one
/// agent commit one after the other — see `ScanQueue::claim_within` for why the count and the take must sit behind a
/// lock, and why the lock is a write. **The row is `agents`'**, so the queue cannot write it itself.
pub trait AgentClaimLock: Send + Sync {
    /// Takes the lock inside `tx`; `false` when the agent no longer exists — nothing to claim for.
    fn lock_for_claim<'a>(
        &'a self,
        tx: &'a mut Tx,
        agent: Uuid,
        at: OffsetDateTime,
    ) -> BoxFuture<'a, Result<bool, PortError>>;
}

/// `agents`' stand-in until task 2.9: **no agent exists**, so a claim for one takes nothing. Nothing can poll without
/// 2.9's routes anyway; a stand-in that took the lock on no row and claimed would hand scans to nobody.
#[derive(Debug, Clone, Copy, Default)]
pub struct AgentsStandIn;

impl AgentClaimLock for AgentsStandIn {
    fn lock_for_claim<'a>(
        &'a self,
        _tx: &'a mut Tx,
        _agent: Uuid,
        _at: OffsetDateTime,
    ) -> BoxFuture<'a, Result<bool, PortError>> {
        Box::pin(async { Ok(false) })
    }
}

/// `ScanRuleSets`: the uploaded Semgrep rules, as a scan needs them — which set is active, a set's files by hash, the
/// languages the rules of a task carrying a hash read.
pub trait ScanRuleSets: Send + Sync {
    /// The active set's content hash, or `None` when only the bundled rules apply.
    fn active_hash(&self) -> BoxFuture<'_, Result<Option<String>, PortError>>;
    /// The files of the set with this hash, or none when no set has it. A stored set that cannot be decoded is an
    /// error, never an empty answer: falling back to the bundled rules would silently narrow every scan.
    fn files_of<'a>(&'a self, content_hash: &'a str) -> BoxFuture<'a, Result<Vec<StoredFile>, PortError>>;
    /// The languages, as `Language` wire names, that the Semgrep rules of a task carrying `content_hash` read — the
    /// bundled rules' and the set's — recorded on the scan when its task is built (decision 0032 §6).
    fn languages_read<'a>(
        &'a self,
        content_hash: Option<&'a str>,
    ) -> BoxFuture<'a, Result<BTreeSet<&'static str>, PortError>>;
}

/// The rule files Vectispire ships — `BundledRules.expected()`, held to `reference/sast/bundled-rules.list`.
pub const BUNDLED_RULE_FILES: [&str; 2] = ["gitleaks/gitleaks.toml", "semgrep/python/dangerous-eval.yaml"];

/// `RuleCoverage.languagesRead`: the languages a rule tree's paths are written for, by their `semgrep/<language>/…`
/// directory — Semgrep's tree only (a gitleaks configuration is no language), a directory naming no language of the
/// vocabulary reaching none.
pub fn languages_read<'a>(paths: impl IntoIterator<Item = &'a str>) -> BTreeSet<&'static str> {
    paths
        .into_iter()
        .filter_map(|path| {
            let normalized = path.replace('\\', "/");
            let segments: Vec<&str> =
                normalized.split('/').filter(|segment| !vectispire_domain::java::is_blank(segment)).collect();
            match segments.as_slice() {
                [first, language, _, ..] if first.eq_ignore_ascii_case("semgrep") => crate::views::language(language),
                _ => None,
            }
        })
        .collect()
}

/// `rules`' stand-in until Phase 3: **no active set** — the bundled rules alone, which is what an installation that
/// never uploaded a set runs (plan §7, the stand-ins table). A task naming a hash cannot be built here, so no task
/// names one; an agent asking for a set's files is answered none.
#[derive(Debug, Clone, Copy, Default)]
pub struct BundledRules;

impl ScanRuleSets for BundledRules {
    fn active_hash(&self) -> BoxFuture<'_, Result<Option<String>, PortError>> {
        Box::pin(async { Ok(None) })
    }

    fn files_of<'a>(&'a self, _content_hash: &'a str) -> BoxFuture<'a, Result<Vec<StoredFile>, PortError>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn languages_read<'a>(
        &'a self,
        _content_hash: Option<&'a str>,
    ) -> BoxFuture<'a, Result<BTreeSet<&'static str>, PortError>> {
        Box::pin(async { Ok(languages_read(BUNDLED_RULE_FILES)) })
    }
}

/// `ScanPlugins`: the plugins a repository's scan runs, each by id and manifest digest, decided when the task is
/// built so two executors cannot disagree about what was run.
pub trait ScanPlugins: Send + Sync {
    /// The enabled plugins activated for the repository's project; none for a repository filed in no project.
    fn for_repository(&self, repository: i64) -> BoxFuture<'_, Result<Vec<PluginRef>, PortError>>;
}

/// `plugins`' stand-in until Phase 4: no plugin, anywhere.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPlugins;

impl ScanPlugins for NoPlugins {
    fn for_repository(&self, _repository: i64) -> BoxFuture<'_, Result<Vec<PluginRef>, PortError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

/// What ingestion prepared outside the writing transaction — end of life asked of a public catalogue, enrichment —
/// opaque to the dispatcher, which hands it back to every attempt of the write.
pub type Prepared = Arc<dyn std::any::Any + Send + Sync>;

/// `ScanIngestor.Reconciliation`: what folding a result into the backlog did, and the built-in types it resolved the
/// backlog against — the set the scan keeps (`ExaminedTypes`), never inferred from the findings present.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reconciliation {
    pub created: i32,
    pub resolved: i32,
    pub reopened: i32,
    pub still_open: i32,
    /// `None` leaves the column as it is.
    pub examined: Option<Vec<FindingType>>,
}

/// Why ingestion did not write.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    /// A person changed an issue the result folds while it was written (the issue's revision, V89): the transaction
    /// rolls back whole and the dispatcher folds again, up to its attempts — a scan is not failed because somebody
    /// triaged.
    #[error("an issue the result folds changed while it was written")]
    Changed,
    #[error(transparent)]
    Failed(PortError),
}

/// `ScanIngestor`: a result into findings — task 2.8's, in `ingestion.rs` and its files. The dispatcher calls
/// [`prepare`](ScanIngestor::prepare) before its transaction and [`ingest`](ScanIngestor::ingest) inside it, after it
/// holds the scan's row.
pub trait ScanIngestor: Send + Sync {
    /// The remote lookups, **before** the writing transaction: inside it they held the row lock that fences a
    /// concurrent reclaim for as long as a public catalogue took to answer.
    fn prepare<'a>(&'a self, scan: &'a ScanView, artifacts: &'a Received<'_>) -> BoxFuture<'a, Prepared>;
    /// The result folded into the scan's findings and the target's backlog, in `tx`.
    fn ingest<'a>(
        &'a self,
        tx: &'a mut Tx,
        scan: &'a ScanView,
        artifacts: &'a Received<'_>,
        prepared: Prepared,
    ) -> BoxFuture<'a, Result<Reconciliation, IngestError>>;
}

/// One call the stand-in received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ingested {
    Prepared { scan: i64 },
    Ingested { scan: i64, observed_nothing: bool },
}

/// Ingestion's stand-in until task 2.8: **records the call** and folds nothing — no finding written, the counts at
/// zero, the examined set left as it was. A scan written through it says "completed" with no findings, which is why
/// the binary must not run scans through it at cut-over; the composition test names it.
#[derive(Debug, Clone, Default)]
pub struct IngestionStandIn {
    calls: Arc<Mutex<Vec<Ingested>>>,
}

impl IngestionStandIn {
    pub fn calls(&self) -> Vec<Ingested> {
        self.calls.lock().map(|calls| calls.clone()).unwrap_or_default()
    }

    fn push(&self, call: Ingested) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(call);
        }
    }
}

impl ScanIngestor for IngestionStandIn {
    fn prepare<'a>(&'a self, scan: &'a ScanView, _artifacts: &'a Received<'_>) -> BoxFuture<'a, Prepared> {
        Box::pin(async move {
            self.push(Ingested::Prepared { scan: scan.id });
            Arc::new(()) as Prepared
        })
    }

    fn ingest<'a>(
        &'a self,
        _tx: &'a mut Tx,
        scan: &'a ScanView,
        artifacts: &'a Received<'_>,
        _prepared: Prepared,
    ) -> BoxFuture<'a, Result<Reconciliation, IngestError>> {
        Box::pin(async move {
            self.push(Ingested::Ingested { scan: scan.id, observed_nothing: artifacts.observed_nothing() });
            Ok(Reconciliation::default())
        })
    }
}

/// `RepositoryScanned`: a reaction to a repository's completed scan, called **in the scan's transaction** and only
/// to queue (decision 0033) — an outbox message in `tx`; what it throws rolls the scan's results back.
pub trait RepositoryScanned: Send + Sync {
    fn scanned<'a>(&'a self, tx: &'a mut Tx, repository: i64, scan: i64) -> BoxFuture<'a, Result<(), PortError>>;
}

/// The built-in worker's runner — `ScanRunner`, task 2.10's, over the pipeline moved out of the agent. Absent on a
/// control plane that scans nothing itself, a legitimate deployment: the dispatcher then claims nothing rather than
/// claiming and failing, which would burn an attempt per round.
pub trait ScanRunner: Send + Sync {
    /// Runs the task, its credentials in the clear. An error is a scan that could not run at all — a step that failed
    /// inside a scan that ran is in the result, absent (decision 0007).
    fn run<'a>(&'a self, task: &'a ScanTask) -> BoxFuture<'a, Result<Received<'static>, RunFailure>>;
}

/// A scan the runner could not run: the executor's sentence, and whether another attempt could pass.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct RunFailure {
    pub message: String,
    pub kind: vectispire_domain::FailureKind,
}
