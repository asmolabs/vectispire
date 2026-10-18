//! The dispatcher — `ScanDispatcher`: it claims scans, has them executed, writes their results, and gives leases back.
//!
//! **Each scan gets its own transaction**, never one for a whole round: a scan that fails must not roll back the
//! result written a moment earlier, and a lease has to be returned without waiting for the others. **Claiming and
//! executing are separate**: a claim is short and transactional, an execution lasts minutes and holds none — it would
//! block PostgreSQL's vacuum and turn a slow scanner into a database incident.
//!
//! **The deployment key only leaves sealed, for a key the agent proved** (decision 0031): an agent in `delegated` mode
//! receives the repository's key or token sealed to the X25519 key it announced signed with its pinned key, under
//! `SealedEnvelope`'s contexts — the token bound to its host and user name, so a proxy that rewrites the host cannot
//! open it. Without a usable sealing key it is handed no such scan at all: the repositories carrying a credential are
//! left out of its selection, and it is told why (the 412) when nothing else was there for it.
//!
//! Its dependencies are ports so that its decisions are held to Java case by case without a database
//! (`tests/claims.rs`, against `reference/scanning/java-answers.json`): the queue ([`DispatchQueue`], answered by
//! `ScanQueue`), the targets' rows ([`TargetRows`], by `cp-targets`), the SAST switch ([`SastSwitch`], by the settings).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_audit::{AuditOperation, Record};
use vectispire_cp_crypto::{Encryption, SecretState, git_token_context, private_key_context};
use vectispire_cp_db::{Db, Tx};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_targets::AuditSink;
use vectispire_cp_targets::credentials::{StoredGitToken, StoredSshKey};
use vectispire_cp_targets::views::{ContainerView, RepositoryView};
use vectispire_crypto::{SealContext, is_usable_sealing_key};
use vectispire_domain::git_host_allowlist::GitHostAllowlist;
use vectispire_domain::scan_queue::Next;
use vectispire_domain::secret::Secret;
use vectispire_domain::{FailureKind, agent_labels, repository_url};
use vectispire_protocol::failure_reason;
use vectispire_protocol::{
    AssignedTask, CredentialsMode, HttpsCredential, Image, ImageReference, Received, ScanTask, Step, Target,
};

use crate::internal::queue::{Abandoned, AgentClaim, Exclusion, NoExclusion, Reclaimed, ScanQueue};
use crate::persistence::{self, ResultWrite, StoreError};
use crate::ports::{
    IngestError, PortError, Prepared, RepositoryScanned, RunFailure, ScanIngestor, ScanPlugins, ScanRuleSets,
    ScanRunner,
};
use crate::views::{PluginOutcome, ScanView, detected_languages, examined_types};

/// How many times a scan's results are folded when an issue changes under them, the first included.
pub const WRITE_ATTEMPTS: u32 = 5;

/// The width of the failure summary on the scan's row.
const SUMMARY_MAX_LENGTH: usize = 2_000;

/// The agent a claim is for — what the dispatcher reads of `agents`' row (`AgentView`), which 2.9 builds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimingAgent {
    pub id: Uuid,
    pub name: Option<String>,
    /// The labels column, as stored: `AgentLabels.parse` reads it.
    pub labels: Option<String>,
    pub max_concurrent: Option<i64>,
    pub credentials_mode: Option<String>,
    pub sealing_public_key: Option<String>,
    pub signing_public_key: Option<String>,
}

impl ClaimingAgent {
    /// The claimant's name on the scans it holds — the agent's identifier, hyphenated.
    pub fn worker(&self) -> String {
        self.id.as_hyphenated().to_string()
    }

    /// `String.valueOf(agent.name())`, as Java concatenates it into a sentence.
    fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or("null")
    }

    /// An unreadable mode reads as `local`: the safe reading of "I do not know what this agent is allowed" is "not the
    /// deployment key".
    fn mode(&self) -> CredentialsMode {
        CredentialsMode::by_wire_name(self.credentials_mode.as_deref()).unwrap_or(CredentialsMode::Local)
    }
}

/// `canBeHandedCredentials`: an agent never handed a credential (`local`, or a mode this version cannot read), or one
/// with a sealing key that verified. **The one predicate the selection and the delivery both come down to**: two tests
/// that could disagree would hand an agent a scan it is then refused, or keep it from one it could have run.
pub fn can_be_handed_credentials(agent: &ClaimingAgent) -> bool {
    !agent.mode().delivers_credentials() || agent.sealing_public_key.as_deref().is_some_and(is_usable_sealing_key)
}

/// `CredentialWithheldException`: a 412, not a 500 — the queue is healthy and the scan still in it, unclaimed with its
/// attempts intact; what is missing is an operator's step, and the sentence names which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.message())]
pub struct CredentialWithheld {
    /// No signing key is pinned for the agent, which is the first thing to fix.
    pub not_pinned: bool,
}

impl CredentialWithheld {
    pub fn message(&self) -> &'static str {
        if self.not_pinned {
            "This agent receives delegated credentials, which are only ever sealed for a sealing key signed with the \
             agent's pinned signing key — and no signing key is pinned for it. Pin one from the agents administration \
             screen and configure its private half as vectispire.agent.signing-key."
        } else {
            "This agent receives delegated credentials, which are only ever sealed for a sealing key signed with the \
             agent's pinned signing key — and it has announced none that verified. An agent announces one at start; \
             one older than this version cannot, and must be updated."
        }
    }

    fn of(agent: &ClaimingAgent) -> CredentialWithheld {
        CredentialWithheld {
            not_pinned: agent.signing_public_key.as_deref().is_none_or(vectispire_domain::java::is_blank),
        }
    }
}

/// Why a claim answered neither a task nor nothing.
#[derive(Debug, thiserror::Error)]
pub enum ClaimError {
    #[error(transparent)]
    Withheld(CredentialWithheld),
    #[error(transparent)]
    Failed(PortError),
}

/// A task and the scan it will have to report against — `AgentTask`.
#[derive(Debug, Clone)]
pub struct AgentTask {
    pub scan_id: i64,
    /// Which attempt of the scan this claim is, from one — what a failure report names, so it can only end that one.
    pub attempt: i32,
    pub task: ScanTask,
}

impl AgentTask {
    /// The claim's answer, as Spring MVC writes it.
    pub fn assigned(&self) -> AssignedTask {
        AssignedTask { scan_id: self.scan_id, attempt: Some(self.attempt), task: self.task.clone() }
    }
}

/// `AgentFailure`: what an agent's report that it could not run its scan did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentFailure {
    pub retried: bool,
    pub attempt: i32,
    pub max_attempts: i32,
    pub permanent: bool,
    pub not_before: Option<OffsetDateTime>,
}

/// One built-in round: how many scans it took, of which `completed + failed` ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dispatched {
    pub claimed: usize,
    pub completed: usize,
    pub failed: usize,
}

/// What the dispatcher asks of the queue — `ScanQueue`, behind a port so its decisions can be held to Java's without a
/// database. Each method is the queue's of the same name.
pub trait DispatchQueue: Send + Sync {
    fn claim<'a>(
        &'a self,
        limit: i64,
        worker: &'a str,
        labels: &'a [String],
    ) -> BoxFuture<'a, Result<Vec<ScanView>, PortError>>;
    fn claim_within<'a>(
        &'a self,
        agent: Uuid,
        limit: i64,
        labels: &'a [String],
        exclusion: &'a dyn Exclusion,
    ) -> BoxFuture<'a, Result<AgentClaim, PortError>>;
    fn count_held<'a>(&'a self, worker: &'a str) -> BoxFuture<'a, Result<i64, PortError>>;
    fn by_id(&self, id: i64) -> BoxFuture<'_, Result<Option<ScanView>, PortError>>;
    fn renew_lease<'a>(&'a self, id: i64, worker: &'a str) -> BoxFuture<'a, Result<bool, PortError>>;
    fn requeue<'a>(&'a self, id: i64, worker: &'a str) -> BoxFuture<'a, Result<bool, PortError>>;
    fn requeue_refunded<'a>(&'a self, id: i64, worker: &'a str) -> BoxFuture<'a, Result<bool, PortError>>;
    fn abandon<'a>(
        &'a self,
        id: i64,
        worker: &'a str,
        attempt: i32,
        kind: FailureKind,
        reason: &'a (dyn Fn(&Abandoned) -> String + Send + Sync),
    ) -> BoxFuture<'a, Result<Option<Abandoned>, PortError>>;
    fn reclaim_lapsed_leases(&self) -> BoxFuture<'_, Result<Reclaimed, PortError>>;
    fn record_sast_languages<'a>(&'a self, id: i64, column: Option<&'a str>) -> BoxFuture<'a, Result<(), PortError>>;
    fn lease(&self) -> Duration;
    /// The scan held for the final write, in `tx` — see `ScanQueue::hold_for_write`.
    fn hold_for_write<'a>(&'a self, tx: &'a mut Tx, id: i64, worker: &'a str)
    -> BoxFuture<'a, Result<bool, PortError>>;
    fn by_id_in<'a>(&'a self, tx: &'a mut Tx, id: i64) -> BoxFuture<'a, Result<Option<ScanView>, PortError>>;
    /// The result's columns written, the claim cleared, in `tx`.
    fn write_result<'a>(&'a self, tx: &'a mut Tx, result: &'a ScanResult) -> BoxFuture<'a, Result<(), PortError>>;
    /// A transaction for the final write.
    fn begin(&self) -> BoxFuture<'_, Result<Tx, PortError>>;
}

/// A finished scan's columns, as the write stores them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub id: i64,
    pub status: &'static str,
    pub findings_count: i32,
    pub new_issues_count: i32,
    pub resolved_issues_count: i32,
    pub duration_ms: Option<i64>,
    pub sbom: Option<String>,
    pub project: Option<(Option<String>, Option<String>)>,
    pub error: Option<String>,
    pub plugin_steps: Option<String>,
    pub detected_languages: Option<String>,
    pub examined_types: Option<String>,
}

fn port(failure: StoreError) -> PortError {
    Box::new(failure)
}

/// `ScanQueue` with its database, as the dispatcher's port.
pub struct QueueOnDatabase {
    pub queue: Arc<ScanQueue>,
    pub db: Db,
}

impl std::fmt::Debug for QueueOnDatabase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("QueueOnDatabase").field("queue", &self.queue).finish_non_exhaustive()
    }
}

impl DispatchQueue for QueueOnDatabase {
    fn claim<'a>(
        &'a self,
        limit: i64,
        worker: &'a str,
        labels: &'a [String],
    ) -> BoxFuture<'a, Result<Vec<ScanView>, PortError>> {
        Box::pin(async move { self.queue.claim(limit, worker, labels).await.map_err(port) })
    }

    fn claim_within<'a>(
        &'a self,
        agent: Uuid,
        limit: i64,
        labels: &'a [String],
        exclusion: &'a dyn Exclusion,
    ) -> BoxFuture<'a, Result<AgentClaim, PortError>> {
        Box::pin(async move { self.queue.claim_within(agent, limit, labels, exclusion).await.map_err(port) })
    }

    fn count_held<'a>(&'a self, worker: &'a str) -> BoxFuture<'a, Result<i64, PortError>> {
        Box::pin(async move { self.queue.count_held(worker).await.map_err(port) })
    }

    fn by_id(&self, id: i64) -> BoxFuture<'_, Result<Option<ScanView>, PortError>> {
        Box::pin(async move { self.queue.by_id(id).await.map_err(port) })
    }

    fn renew_lease<'a>(&'a self, id: i64, worker: &'a str) -> BoxFuture<'a, Result<bool, PortError>> {
        Box::pin(async move { self.queue.renew_lease(id, worker).await.map_err(port) })
    }

    fn requeue<'a>(&'a self, id: i64, worker: &'a str) -> BoxFuture<'a, Result<bool, PortError>> {
        Box::pin(async move { self.queue.requeue(id, worker).await.map_err(port) })
    }

    fn requeue_refunded<'a>(&'a self, id: i64, worker: &'a str) -> BoxFuture<'a, Result<bool, PortError>> {
        Box::pin(async move { self.queue.requeue_refunded(id, worker).await.map_err(port) })
    }

    fn abandon<'a>(
        &'a self,
        id: i64,
        worker: &'a str,
        attempt: i32,
        kind: FailureKind,
        reason: &'a (dyn Fn(&Abandoned) -> String + Send + Sync),
    ) -> BoxFuture<'a, Result<Option<Abandoned>, PortError>> {
        Box::pin(async move { self.queue.abandon(id, worker, attempt, kind, reason).await.map_err(port) })
    }

    fn reclaim_lapsed_leases(&self) -> BoxFuture<'_, Result<Reclaimed, PortError>> {
        Box::pin(async move { self.queue.reclaim_lapsed_leases().await.map_err(port) })
    }

    fn record_sast_languages<'a>(&'a self, id: i64, column: Option<&'a str>) -> BoxFuture<'a, Result<(), PortError>> {
        Box::pin(async move { self.queue.record_sast_languages(id, column).await.map_err(port) })
    }

    fn lease(&self) -> Duration {
        self.queue.lease()
    }

    fn hold_for_write<'a>(
        &'a self,
        tx: &'a mut Tx,
        id: i64,
        worker: &'a str,
    ) -> BoxFuture<'a, Result<bool, PortError>> {
        Box::pin(async move { self.queue.hold_for_write(tx, id, worker).await.map_err(port) })
    }

    fn by_id_in<'a>(&'a self, tx: &'a mut Tx, id: i64) -> BoxFuture<'a, Result<Option<ScanView>, PortError>> {
        Box::pin(async move { self.queue.by_id_in(tx, id).await.map_err(port) })
    }

    fn write_result<'a>(&'a self, tx: &'a mut Tx, result: &'a ScanResult) -> BoxFuture<'a, Result<(), PortError>> {
        Box::pin(async move {
            let write = ResultWrite {
                id: result.id,
                status: result.status.to_owned(),
                findings_count: result.findings_count,
                new_issues_count: result.new_issues_count,
                resolved_issues_count: result.resolved_issues_count,
                duration_ms: result.duration_ms,
                sbom: result.sbom.clone(),
                project: result.project.clone(),
                error: result.error.clone(),
                plugin_steps: result.plugin_steps.clone(),
                detected_languages: result.detected_languages.clone(),
                examined_types: result.examined_types.clone(),
            };
            persistence::write_result(tx, &write).await.map(|_| ()).map_err(port)
        })
    }

    fn begin(&self) -> BoxFuture<'_, Result<Tx, PortError>> {
        Box::pin(async move { persistence::write(&self.db).await.map_err(port) })
    }
}

/// What the dispatcher reads of a target — `TargetCatalog` and `CloneCredentials`, answered by `cp-targets`. The
/// credentials come **still encrypted**, decrypted here and only here.
pub trait TargetRows: Send + Sync {
    fn repository(&self, id: i64) -> BoxFuture<'_, Result<Option<RepositoryView>, PortError>>;
    fn container(&self, id: i64) -> BoxFuture<'_, Result<Option<ContainerView>, PortError>>;
    /// Those of these repositories cloned with a credential of their own.
    fn carrying_credentials<'a>(&'a self, ids: &'a BTreeSet<i64>) -> BoxFuture<'a, Result<BTreeSet<i64>, PortError>>;
    fn git_token(&self, id: Uuid) -> BoxFuture<'_, Result<Option<StoredGitToken>, PortError>>;
    fn ssh_key(&self, id: Uuid) -> BoxFuture<'_, Result<Option<StoredSshKey>, PortError>>;
}

impl TargetRows for vectispire_cp_targets::Targets {
    fn repository(&self, id: i64) -> BoxFuture<'_, Result<Option<RepositoryView>, PortError>> {
        Box::pin(async move { self.catalog_repository(id).await.map_err(|failure| Box::new(failure) as PortError) })
    }

    fn container(&self, id: i64) -> BoxFuture<'_, Result<Option<ContainerView>, PortError>> {
        Box::pin(async move { self.catalog_container(id).await.map_err(|failure| Box::new(failure) as PortError) })
    }

    fn carrying_credentials<'a>(&'a self, ids: &'a BTreeSet<i64>) -> BoxFuture<'a, Result<BTreeSet<i64>, PortError>> {
        Box::pin(async move {
            vectispire_cp_targets::Targets::carrying_credentials(self, ids)
                .await
                .map_err(|failure| Box::new(failure) as PortError)
        })
    }

    fn git_token(&self, id: Uuid) -> BoxFuture<'_, Result<Option<StoredGitToken>, PortError>> {
        Box::pin(async move { self.stored_git_token(id).await.map_err(|failure| Box::new(failure) as PortError) })
    }

    fn ssh_key(&self, id: Uuid) -> BoxFuture<'_, Result<Option<StoredSshKey>, PortError>> {
        Box::pin(async move { self.stored_ssh_key(id).await.map_err(|failure| Box::new(failure) as PortError) })
    }
}

/// Whether the SAST step is on — `Setting.SAST_ENABLED`, read here and put on the task, never read by the executor: a
/// remote agent has no database, and two executors asking for themselves could diverge on the same target.
pub trait SastSwitch: Send + Sync {
    fn sast_enabled(&self) -> BoxFuture<'_, Result<bool, PortError>>;
}

impl SastSwitch for vectispire_cp_settings::Settings {
    fn sast_enabled(&self) -> BoxFuture<'_, Result<bool, PortError>> {
        Box::pin(async move {
            self.is_enabled(vectispire_cp_settings::Setting::SastEnabled)
                .await
                .map_err(|failure| Box::new(failure) as PortError)
        })
    }
}

/// An agent's exclusion asked of the targets' owner a page at a time: the repositories that carry a credential.
struct CarryingCredentials<'a>(&'a dyn TargetRows);

impl Exclusion for CarryingCredentials<'_> {
    fn among<'b>(&'b self, repositories: &'b BTreeSet<i64>) -> BoxFuture<'b, Result<BTreeSet<i64>, PortError>> {
        self.0.carrying_credentials(repositories)
    }
}

/// A task this control plane would not build, or could not: the sentence, and whether another attempt could pass.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TaskFailure {
    message: String,
    kind: FailureKind,
}

impl TaskFailure {
    /// `TaskRefused`: a reason no later attempt changes — target gone, URL refused, credential deleted or sealed under
    /// no key configured here. Permanent, so the scan fails with the reason instead of spending its attempts on it.
    fn refused(message: impl Into<String>) -> TaskFailure {
        TaskFailure { message: message.into(), kind: FailureKind::Permanent }
    }

    /// Anything else — a store that did not answer: transient, when in doubt.
    fn transient(failure: impl std::fmt::Display) -> TaskFailure {
        TaskFailure { message: failure.to_string(), kind: FailureKind::Transient }
    }
}

/// What `claim_for_agent`'s guarded part ends in.
enum Delivery {
    Task(Box<AgentTask>),
    Withheld(CredentialWithheld),
    Failed(TaskFailure),
}

/// What the dispatcher is built from.
#[allow(missing_debug_implementations)] // Ports: nothing a log line should print.
pub struct DispatcherConfig {
    pub queue: Arc<dyn DispatchQueue>,
    pub targets: Arc<dyn TargetRows>,
    pub encryption: Arc<Encryption>,
    pub sast: Arc<dyn SastSwitch>,
    pub rule_sets: Arc<dyn ScanRuleSets>,
    pub plugins: Arc<dyn ScanPlugins>,
    pub ingestor: Arc<dyn ScanIngestor>,
    pub audit: Arc<dyn AuditSink>,
    pub allowed_hosts: GitHostAllowlist,
    /// `vectispire.scanning.image-platform`: the variant of an image to pull — a decision about *what we want
    /// scanned*, not about the machine that runs the scan. Blank is none.
    pub image_platform: Option<String>,
    /// The built-in worker's runner (2.10); `None` claims nothing for it.
    pub runner: Option<Arc<dyn ScanRunner>>,
    /// Told of every repository's completed scan, in its transaction.
    pub scanned: Vec<Arc<dyn RepositoryScanned>>,
}

/// The dispatcher.
pub struct ScanDispatcher {
    queue: Arc<dyn DispatchQueue>,
    targets: Arc<dyn TargetRows>,
    encryption: Arc<Encryption>,
    sast: Arc<dyn SastSwitch>,
    rule_sets: Arc<dyn ScanRuleSets>,
    plugins: Arc<dyn ScanPlugins>,
    ingestor: Arc<dyn ScanIngestor>,
    audit: Arc<dyn AuditSink>,
    allowed_hosts: GitHostAllowlist,
    image_platform: Option<String>,
    runner: Option<Arc<dyn ScanRunner>>,
    scanned: Vec<Arc<dyn RepositoryScanned>>,
}

impl std::fmt::Debug for ScanDispatcher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScanDispatcher")
            .field("allowed_hosts", &self.allowed_hosts)
            .field("image_platform", &self.image_platform)
            .field("runs_scans_here", &self.runner.is_some())
            .finish_non_exhaustive()
    }
}

impl ScanDispatcher {
    pub fn new(config: DispatcherConfig) -> ScanDispatcher {
        ScanDispatcher {
            queue: config.queue,
            targets: config.targets,
            encryption: config.encryption,
            sast: config.sast,
            rule_sets: config.rule_sets,
            plugins: config.plugins,
            ingestor: config.ingestor,
            audit: config.audit,
            allowed_hosts: config.allowed_hosts,
            image_platform: config.image_platform.filter(|platform| !platform.trim().is_empty()),
            runner: config.runner,
            scanned: config.scanned,
        }
    }

    /// Whether this control plane scans anything itself: without a runner the built-in worker claims nothing,
    /// whatever its configuration says.
    pub fn runs_scans_here(&self) -> bool {
        self.runner.is_some()
    }

    // ── remote agents ────────────────────────────────────────────────────────────────────────

    /// `claimForAgent`: one task for a remote agent, or nothing when the queue has none for it or it already runs its
    /// limit. **Single-shot**: the waiting belongs to the long poll (2.9), which holds a connection, not a thread.
    ///
    /// **Within the agent's limit, counted by the database** — the agent stops polling at its limit too, but two
    /// processes sharing a key would each believe they had room. **Such an agent does not claim a scan it could not be
    /// handed**: it used to, each claim counting an attempt, and a scan nothing had tried reached the executor that
    /// could run it with its takeovers spent.
    pub async fn claim_for_agent(&self, agent: &ClaimingAgent) -> Result<Option<AgentTask>, ClaimError> {
        let labels = agent_labels::parse(agent.labels.as_deref());
        let limit = i64::from(vectispire_protocol::concurrency::effective(agent.max_concurrent));
        let worker = agent.worker();
        // Asked only of an agent that cannot be handed a credential: every other poll costs what it cost before.
        let carrying = CarryingCredentials(self.targets.as_ref());
        let exclusion: &dyn Exclusion = if can_be_handed_credentials(agent) { &NoExclusion } else { &carrying };
        let claim = self.queue.claim_within(agent.id, limit, &labels, exclusion).await.map_err(ClaimError::Failed)?;
        let Some(scan) = claim.scan else {
            // Not when the agent is full: it would have been handed nothing anyway, and the answer would name a
            // missing key as the reason for a limit.
            if claim.kept && self.queue.count_held(&worker).await.map_err(ClaimError::Failed)? < limit {
                return Err(ClaimError::Withheld(CredentialWithheld::of(agent)));
            }
            return Ok(None);
        };
        let mut built = None;
        match self.deliver(agent, &worker, &scan, &mut built).await {
            Delivery::Task(task) => Ok(Some(*task)),
            Delivery::Withheld(withheld) => Err(ClaimError::Withheld(withheld)),
            // The same rule as the agent's own report and the built-in worker's: a URL the allow-list now refuses
            // fails at once, a key store that did not answer retries.
            Delivery::Failed(failure) => {
                let place = format!("for agent \"{}\"", agent.display_name());
                self.abandon(&scan, &worker, &place, &failure, built.as_ref()).await.map_err(ClaimError::Failed)?;
                Ok(None)
            }
        }
    }

    async fn deliver(
        &self,
        agent: &ClaimingAgent,
        worker: &str,
        scan: &ScanView,
        built: &mut Option<ScanTask>,
    ) -> Delivery {
        // **The agent's mode decides**: an agent in `local` mode never has a key to receive, so the key is neither read
        // nor decrypted — one does not decrypt a secret one will not send.
        let mut task = match self.build_task(scan, agent.mode().delivers_credentials()).await {
            Ok(task) => task,
            Err(failure) => return Delivery::Failed(failure),
        };
        *built = Some(task.clone());
        let Target::Repository(repository) = &mut task.target else {
            return Delivery::Task(Box::new(AgentTask { scan_id: scan.id, attempt: scan.attempts, task }));
        };
        if repository.private_key.is_none() && repository.https.is_none() {
            return Delivery::Task(Box::new(AgentTask { scan_id: scan.id, attempt: scan.attempts, task }));
        }
        // **Sealed for the verified key, or not sent at all.** There is no clear fallback, over TLS or otherwise.
        let Some(sealing_key) = agent.sealing_public_key.as_deref().filter(|key| is_usable_sealing_key(key)) else {
            // Reached through a race only: the selection left out every repository carrying a credential when it read
            // them, and this one gained its key since. Put back *before* refusing, with its attempt refunded since
            // nothing was tried; the next selection reads the key and leaves the repository out, so the refund is paid
            // once.
            if let Err(failure) = self.queue.requeue_refunded(scan.id, worker).await {
                return Delivery::Failed(TaskFailure::transient(failure));
            }
            return Delivery::Withheld(CredentialWithheld::of(agent));
        };
        if let Some(key) = &repository.private_key {
            match vectispire_crypto::seal(sealing_key, key.expose(), &SealContext::deployment_key()) {
                Ok(envelope) => repository.private_key = Some(Secret::new(envelope)),
                Err(failure) => return Delivery::Failed(TaskFailure::transient(failure)),
            }
        }
        // The token is sealed as the key is (decision 0022), **under its host and user name**: they travel in the
        // clear, and a TLS-terminating proxy that rewrote the host used to receive the token.
        if let Some(https) = &mut repository.https
            && let Some(token) = &https.token
        {
            let context = SealContext::https_token(https.host.as_deref(), https.username.as_deref());
            match vectispire_crypto::seal(sealing_key, token.expose(), &context) {
                Ok(envelope) => https.token = Some(Secret::new(envelope)),
                Err(failure) => return Delivery::Failed(TaskFailure::transient(failure)),
            }
        }
        self.record_credential_sent(agent, scan.id, "sealed for the agent's verified sealing key").await;
        Delivery::Task(Box::new(AgentTask { scan_id: scan.id, attempt: scan.attempts, task }))
    }

    /// `AGENT_CREDENTIAL_SENT`: a deployment key left the control plane — the question afterwards is "which machines
    /// have held this repository's key".
    async fn record_credential_sent(&self, agent: &ClaimingAgent, scan: i64, how: &str) {
        self.audit
            .record(Record {
                operation: AuditOperation::AgentCredentialSent,
                resource_id: Some(scan.to_string()),
                description: Some(format!(
                    "Deployment key delegated to agent \"{}\" for scan {scan}, {how}.",
                    agent.display_name()
                )),
                user_id: agent.name.clone(),
                ip_address: None,
                user_agent: None,
                signal: None,
            })
            .await;
    }

    /// `returnUndelivered`: a scan claimed for an agent that never received it, put back — only while the claim is
    /// still that agent's, and **without a refund**: a scan that keeps going undelivered should reach its limit.
    pub async fn return_undelivered(&self, scan_id: i64, agent: &ClaimingAgent) -> Result<(), PortError> {
        if self.queue.requeue(scan_id, &agent.worker()).await? {
            tracing::info!(
                scan_id,
                agent = agent.display_name(),
                "A scan claimed but never delivered is back in the queue."
            );
        }
        Ok(())
    }

    /// `renewAgentLease`.
    pub async fn renew_agent_lease(&self, scan_id: i64, agent: &ClaimingAgent) -> Result<bool, PortError> {
        self.queue.renew_lease(scan_id, &agent.worker()).await
    }

    /// `acceptAgentResult`: the result of a scan executed elsewhere — `false` when the lease was taken over meanwhile,
    /// the results then discarded rather than written over the successor's. `alongside` writes in the result's
    /// transaction — the route's audit message in the outbox (decision 0033) — and commits with it or not at all.
    pub async fn accept_agent_result(
        &self,
        scan_id: i64,
        agent: &ClaimingAgent,
        artifacts: &Received<'_>,
        alongside: Option<&(dyn Alongside + '_)>,
    ) -> Result<bool, PortError> {
        self.record(scan_id, &agent.worker(), artifacts, alongside).await
    }

    /// `reportAgentFailure`: an agent's word that it could not run the scan it claimed — anything before a result
    /// exists — ending that attempt now, with the reason on the scan, rather than after the lapse's twenty minutes.
    /// Only while the scan is still this agent's, at that attempt. `reason` arrives scrubbed.
    pub async fn report_agent_failure(
        &self,
        scan_id: i64,
        agent: &ClaimingAgent,
        attempt: i32,
        kind: FailureKind,
        reason: &str,
    ) -> Result<Option<AgentFailure>, PortError> {
        let place = format!("on agent \"{}\"", agent.display_name());
        let sentence = |outcome: &Abandoned| sentence(outcome, &place, reason);
        let abandoned = self.queue.abandon(scan_id, &agent.worker(), attempt, kind, &sentence).await?;
        if let Some(done) = &abandoned {
            log_abandoned(scan_id, &place, done);
        }
        Ok(abandoned.map(|done| AgentFailure {
            retried: done.retried(),
            attempt: done.attempt,
            max_attempts: done.max_attempts,
            permanent: done.permanent(),
            not_before: done.not_before(),
        }))
    }

    // ── the built-in worker ──────────────────────────────────────────────────────────────────

    /// `dispatch`: one round — lost leases reclaimed, then claims within `max_concurrent` **of this worker's own
    /// scans**, never of the queue's (a fleet of agents holding forty scans left the built-in worker idle on a machine
    /// doing nothing), executed one after the other: how much fits was decided by the number claimed.
    pub async fn dispatch(
        &self,
        worker: &str,
        max_concurrent: i32,
        labels: &[String],
    ) -> Result<Dispatched, PortError> {
        self.reclaim_lost_leases().await?;
        let Some(runner) = &self.runner else { return Ok(Dispatched::default()) };
        let held = i32::try_from(self.queue.count_held(worker).await?).unwrap_or(i32::MAX);
        let room = vectispire_domain::scan_queue::capacity(max_concurrent, held);
        if room == 0 {
            return Ok(Dispatched::default());
        }
        let claimed = self.queue.claim(i64::from(room), worker, labels).await?;
        let mut dispatched = Dispatched { claimed: claimed.len(), ..Dispatched::default() };
        for scan in &claimed {
            if self.execute(runner.as_ref(), scan, worker).await? {
                dispatched.completed += 1;
            } else {
                dispatched.failed += 1;
            }
        }
        Ok(dispatched)
    }

    async fn reclaim_lost_leases(&self) -> Result<(), PortError> {
        let reclaimed = self.queue.reclaim_lapsed_leases().await?;
        if !reclaimed.requeued.is_empty() {
            tracing::warn!(scans = reclaimed.requeued.len(), "Abandoned scan(s) put back in the queue.");
        }
        if !reclaimed.failed.is_empty() {
            tracing::error!(scans = reclaimed.failed.len(), "Scan(s) failed for good after too many takeovers.");
        }
        Ok(())
    }

    /// One scan on the built-in worker: `true` when it finished normally.
    async fn execute(&self, runner: &dyn ScanRunner, scan: &ScanView, worker: &str) -> Result<bool, PortError> {
        const PLACE: &str = "on the built-in worker";
        // **Renewed before it starts**: a round's scans are all leased from the claim, and the third could lapse before
        // it began, be reclaimed elsewhere, and run twice.
        if !self.queue.renew_lease(scan.id, worker).await? {
            tracing::warn!(scan = scan.id, "A scan was taken over before it started — skipped.");
            return Ok(false);
        }
        let heartbeat = self.keep_leased(scan.id, worker);
        // The built-in worker runs inside the control plane and always receives the key. Outside a transaction.
        let mut built = None;
        let ran = async {
            let task = self.build_task(scan, true).await?;
            built = Some(task.clone());
            runner.run(&task).await.map_err(|RunFailure { message, kind }| TaskFailure { message, kind })
        }
        .await;
        heartbeat.abort();
        let artifacts = match ran {
            Ok(artifacts) => artifacts,
            Err(failure) => {
                // **The agents' rule, not one of its own**: a network blip that cost an agent one attempt of three
                // used to cost the built-in worker the scan.
                self.abandon(scan, worker, PLACE, &failure, built.as_ref()).await?;
                return Ok(false);
            }
        };
        match self.record(scan.id, worker, &artifacts, None).await {
            Ok(written) => {
                if !written {
                    tracing::warn!(scan = scan.id, "A scan was taken over while it ran — results discarded.");
                }
                Ok(true)
            }
            // Its results could not be written and the write rolled back: the scan is still this worker's, as an
            // agent's is when its upload fails — a transient failure, without the lapse's twenty minutes.
            Err(failure) => {
                self.abandon(scan, worker, PLACE, &TaskFailure::transient(failure), built.as_ref()).await?;
                Ok(false)
            }
        }
    }

    /// `keepLeased`: the lease renewed every third of it while the built-in worker runs — two renewals can be lost
    /// before it lapses. Only remote agents renewed once; any scan longer than the lease was reclaimed while it ran,
    /// executed twice, and failed "lease exhausted" on a target that was simply slow. A failed renewal is logged and
    /// the next one tried: if the scan was taken over, the write will say so.
    fn keep_leased(&self, scan: i64, worker: &str) -> tokio::task::JoinHandle<()> {
        let queue = self.queue.clone();
        let worker = worker.to_owned();
        let period = (queue.lease() / 3).max(Duration::from_secs(1));
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            loop {
                ticks.tick().await;
                match queue.renew_lease(scan, &worker).await {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::warn!(scan, "A scan is no longer this worker's — its results will be discarded.")
                    }
                    Err(failure) => tracing::warn!(scan, error = %failure, "A lease renewal failed."),
                }
            }
        })
    }

    /// Ends an attempt that failed here by an agent's report's rule: the kind the failure carries, the reason
    /// **scrubbed** of what the task held and of what has a secret's shape — it reaches the row every account that
    /// sees the target reads, and a clone's message can quote what the clone held.
    async fn abandon(
        &self,
        scan: &ScanView,
        worker: &str,
        place: &str,
        failure: &TaskFailure,
        task: Option<&ScanTask>,
    ) -> Result<(), PortError> {
        let secrets: Vec<Option<&str>> = task.map_or_else(Vec::new, |task| match &task.target {
            Target::Repository(repository) => vec![
                repository.private_key.as_ref().map(Secret::expose),
                repository.https.as_ref().and_then(|https| https.token.as_ref()).map(Secret::expose),
            ],
            Target::Image(_) => Vec::new(),
        });
        let reason = failure_reason::scrub(&failure.message, secrets);
        let reason = if reason.is_empty() { "no reason was given.".to_owned() } else { reason };
        let sentence = |outcome: &Abandoned| sentence(outcome, place, &reason);
        if let Some(done) = self.queue.abandon(scan.id, worker, scan.attempts, failure.kind, &sentence).await? {
            log_abandoned(scan.id, place, &done);
        }
        Ok(())
    }

    // ── the result ───────────────────────────────────────────────────────────────────────────

    /// `record`: a finished scan's results, written if this worker still owns it. **The remote lookups first, then the
    /// transaction**; **folded again, never failed, when a person wrote an issue meanwhile** — the issue's revision
    /// refuses the save, the transaction rolls back whole, the next attempt reads the person's decision.
    async fn record(
        &self,
        scan_id: i64,
        worker: &str,
        artifacts: &Received<'_>,
        alongside: Option<&(dyn Alongside + '_)>,
    ) -> Result<bool, PortError> {
        let Some(scan) = self.queue.by_id(scan_id).await? else { return Ok(false) };
        let prepared = self.ingestor.prepare(&scan, artifacts).await;
        let mut attempt = 1;
        loop {
            let mut tx = self.queue.begin().await?;
            match self.write(&mut tx, scan_id, worker, artifacts, prepared.clone(), alongside).await {
                Ok(written) => {
                    tx.commit().await.map_err(|failure| Box::new(failure) as PortError)?;
                    return Ok(written);
                }
                Err(WriteError::Changed) if attempt < WRITE_ATTEMPTS => {
                    let _ = tx.rollback().await;
                    attempt += 1;
                    tracing::info!(
                        scan_id,
                        attempt,
                        "An issue the result folds changed while it was written; folding again."
                    );
                }
                Err(failure) => {
                    let _ = tx.rollback().await;
                    return Err(match failure {
                        WriteError::Changed => Box::new(IngestError::Changed),
                        WriteError::Failed(failure) => failure,
                    });
                }
            }
        }
    }

    async fn write(
        &self,
        tx: &mut Tx,
        scan_id: i64,
        worker: &str,
        artifacts: &Received<'_>,
        prepared: Prepared,
        alongside: Option<&(dyn Alongside + '_)>,
    ) -> Result<bool, WriteError> {
        // Holds the row until this transaction commits.
        if !self.queue.hold_for_write(tx, scan_id, worker).await? {
            return Ok(false);
        }
        let Some(scan) = self.queue.by_id_in(tx, scan_id).await? else { return Ok(false) };
        let folded = match self.ingestor.ingest(tx, &scan, artifacts, prepared).await {
            Ok(folded) => folded,
            Err(IngestError::Changed) => return Err(WriteError::Changed),
            Err(IngestError::Failed(failure)) => return Err(WriteError::Failed(failure)),
        };
        let result = result_of(&scan, artifacts, &folded)?;
        self.queue.write_result(tx, &result).await?;
        if let Some(alongside) = alongside {
            alongside.write(tx).await?;
        }
        // Told in the scan's transaction, here where both executors' results pass (decision 0033).
        if let Some(repository) = scan.repo_id
            && result.status == "completed"
        {
            for reaction in &self.scanned {
                reaction.scanned(tx, repository, scan.id).await?;
            }
        }
        Ok(true)
    }

    // ── the task ─────────────────────────────────────────────────────────────────────────────

    /// `buildTask`: the private key decrypted here, and only here. `deliver_credentials` is **an authorization
    /// decision**: false for an agent in `local` mode, and the key is then neither read nor decrypted.
    async fn build_task(&self, scan: &ScanView, deliver_credentials: bool) -> Result<ScanTask, TaskFailure> {
        let Some(repository_id) = scan.repo_id else { return self.build_image_task(scan).await };
        let repository = self
            .targets
            .repository(repository_id)
            .await
            .map_err(TaskFailure::transient)?
            .ok_or_else(|| TaskFailure::refused(format!("Repository {repository_id} no longer exists.")))?;
        // The URL's own rules before its host is judged: a row registered before a rule existed is refused before its
        // task and its credential leave for an agent. Then the allow-list, again here and not only at entry: a list
        // tightened after a repository was registered stops its scans too.
        if let Some(reason) = repository_url::validate(&repository.url) {
            return Err(TaskFailure::refused(format!("Repository URL refused: {reason}")));
        }
        if !self.allowed_hosts.permits(&repository.url) {
            return Err(TaskFailure::refused(self.allowed_hosts.refusal(&repository_url::redact(&repository.url))));
        }
        let mut https = None;
        if let (Some(token_id), true) = (repository.https_token_id, deliver_credentials) {
            let token = self.targets.git_token(token_id).await.map_err(TaskFailure::transient)?.ok_or_else(|| {
                TaskFailure::refused(format!(
                    "The HTTPS token of repository {} has been deleted.",
                    repository_url::redact(&repository.url)
                ))
            })?;
            let secret = self.encryption.inspect(&token.ciphertext, &git_token_context(&token.id.to_string())).await;
            if secret.state() == SecretState::Unreadable {
                return Err(TaskFailure::refused(format!(
                    "The HTTPS token \"{}\" cannot be decrypted by any configured encryption key.",
                    token.name
                )));
            }
            https = Some(HttpsCredential {
                host: Some(token.host.clone()),
                username: token.username.clone(),
                token: Some(Secret::new(secret.plain_text())),
            });
        }
        let mut private_key = None;
        if let (Some(key_id), true) = (repository.ssh_key_id, deliver_credentials) {
            let key = self.targets.ssh_key(key_id).await.map_err(TaskFailure::transient)?.ok_or_else(|| {
                TaskFailure::refused(format!(
                    "The SSH key of repository {} has been deleted.",
                    repository_url::redact(&repository.url)
                ))
            })?;
            let secret = self.encryption.inspect(&key.ciphertext, &private_key_context(&key.id.to_string())).await;
            if secret.state() == SecretState::Unreadable {
                // Said explicitly: otherwise it would look like a refusal from the git server, and the operator would
                // go looking at the provider.
                return Err(TaskFailure::refused(format!(
                    "The SSH key \"{}\" cannot be decrypted by any configured encryption key.",
                    key.name
                )));
            }
            private_key = Some(Secret::new(secret.plain_text()));
        }
        let branch = if vectispire_domain::java::is_blank(&scan.branch) {
            repository.branch.clone()
        } else {
            scan.branch.clone()
        };
        let mut steps: BTreeSet<Step> = [Step::Dependencies, Step::Secrets, Step::Iac].into_iter().collect();
        if self.sast.sast_enabled().await.map_err(TaskFailure::transient)? {
            steps.insert(Step::Sast);
        }
        // **Set by the control plane, never read by the executor**: an agent asking for "the active set" itself would
        // scan with whatever it found when it asked, and two agents could diverge on the same target.
        let rules_hash = self.rule_sets.active_hash().await.map_err(TaskFailure::transient)?;
        // The languages those rules read, kept from the very hash the task carries — written again at every build, so
        // a scan taken over after a lapse keeps the rules its last task carried.
        let column = if steps.contains(&Step::Sast) {
            let read = self.rule_sets.languages_read(rules_hash.as_deref()).await.map_err(TaskFailure::transient)?;
            detected_languages::write(Some(read.into_iter()))
        } else {
            None
        };
        self.queue.record_sast_languages(scan.id, column.as_deref()).await.map_err(TaskFailure::transient)?;
        let plugins = self.plugins.for_repository(repository.id).await.map_err(TaskFailure::transient)?;
        Ok(ScanTask {
            target: Target::Repository(vectispire_protocol::Repository {
                url: repository.url.clone(),
                branch: Some(branch),
                sub_path: Some(repository.sub_path.clone().unwrap_or_default()),
                private_key,
                https,
            }),
            rules_hash,
            steps,
            plugins,
        })
    }

    /// An image's task: **no key is ever sent**, whatever the mode — an image is pulled from a registry, whose
    /// credentials belong to the scanning machine's Docker configuration. Its dependencies alone: a registry image has
    /// no tree to grep, and the OWASP grid assumes an image is never examined for the rest.
    async fn build_image_task(&self, scan: &ScanView) -> Result<ScanTask, TaskFailure> {
        let Some(container_id) = scan.container_id else {
            return Err(TaskFailure::refused(format!("Scan {} names neither a repository nor a container.", scan.id)));
        };
        let container = self
            .targets
            .container(container_id)
            .await
            .map_err(TaskFailure::transient)?
            .ok_or_else(|| TaskFailure::refused(format!("Container {container_id} no longer exists.")))?;
        Ok(ScanTask {
            target: Target::Image(Image {
                reference: ImageReference {
                    registry: container.registry.clone(),
                    image_name: container.image_name.clone(),
                    tag: container.tag.clone(),
                },
                platform: self.image_platform.clone(),
            }),
            rules_hash: None,
            steps: [Step::Dependencies].into_iter().collect(),
            plugins: Vec::new(),
        })
    }
}

/// Something written in the result's transaction, only when the result is: the agent route's audit message.
pub trait Alongside: Send + Sync {
    fn write<'a>(&'a self, tx: &'a mut Tx) -> BoxFuture<'a, Result<(), PortError>>;
}

enum WriteError {
    Changed,
    Failed(PortError),
}

impl From<PortError> for WriteError {
    fn from(failure: PortError) -> WriteError {
        WriteError::Failed(failure)
    }
}

/// The scan's columns after a result, as Java's write sets them on the entity.
fn result_of(
    scan: &ScanView,
    artifacts: &Received<'_>,
    folded: &crate::ports::Reconciliation,
) -> Result<ScanResult, PortError> {
    // **A scan that observed nothing, with something broken, is a failure**: the target was never examined — an image
    // whose name does not exist, the pull failing and taking every step with it, reached the screen as clean. Nothing
    // observed and nothing failed stays completed: a task asked to run no step is a configuration to look at.
    let nothing_examined = artifacts.observed_nothing() && !artifacts.failures.is_empty();
    Ok(ScanResult {
        id: scan.id,
        status: if nothing_examined { "failed" } else { "completed" },
        findings_count: folded.created.saturating_add(folded.reopened).saturating_add(folded.still_open),
        new_issues_count: folded.created,
        resolved_issues_count: folded.resolved,
        // Unknown rather than a crash: a result without a duration is still a result.
        duration_ms: artifacts.duration.map(java_millis).transpose()?,
        sbom: artifacts.sbom.as_ref().map(|raw| sbom_text(raw.get())).transpose()?,
        // Left alone when absent: a clone that carried no manifest says nothing about the target's ecosystem.
        project: artifacts.project.as_ref().map(|project| (project.kind.clone(), project.version.clone())),
        // Step failures are recorded on a successful scan too: otherwise nobody knows one scanner looked at nothing.
        error: failure_summary(artifacts)?,
        plugin_steps: PluginOutcome::write(&artifacts.plugins.iter().map(outcome_of).collect::<Vec<_>>()),
        // Written, not left alone when absent: the column describes this scan's tree, and `None` is "unknown".
        detected_languages: detected_languages::write(
            artifacts.languages.as_ref().map(|set| set.iter().map(String::as_str)),
        ),
        examined_types: folded.examined.as_deref().map(examined_types::write),
    })
}

/// `Duration.toMillis`, `ArithmeticException` past a `long`: the write fails, as Java's does.
fn java_millis(duration: vectispire_protocol::JavaDuration) -> Result<i64, PortError> {
    duration
        .seconds
        .checked_mul(1_000)
        .and_then(|millis| millis.checked_add(i64::from(duration.nanos / 1_000_000)))
        .ok_or_else(|| "long overflow".into())
}

/// `JsonNode.toString()`: what Java stores of the SBOM is the tree Jackson read, written back compact — not the bytes
/// as sent. Read as a tree with the document's member order (a duplicate member keeping its first place and its last
/// value, as an `ObjectNode` does) and written by `wire`, which escapes and writes doubles as Jackson does.
fn sbom_text(raw: &str) -> Result<String, PortError> {
    let mut reader = serde_json::Deserializer::from_str(raw);
    // The body's depth is already bounded by the reader (1,000, Jackson 2's); serde's own 128 would refuse it.
    reader.disable_recursion_limit();
    let tree: serde_json::Value = serde::Deserialize::deserialize(&mut reader)?;
    Ok(vectispire_domain::wire::to_wire_string(&tree))
}

/// `failureSummary`: `step: reason`, joined by ` | `, within the column — `None` when nothing failed. A `null` element
/// is Java's `NullPointerException`: the write fails, and the scan is abandoned as a write that failed.
fn failure_summary(artifacts: &Received<'_>) -> Result<Option<String>, PortError> {
    if artifacts.failures.is_empty() {
        return Ok(None);
    }
    let mut parts = Vec::with_capacity(artifacts.failures.len());
    for failure in &artifacts.failures {
        let failure = failure.as_ref().ok_or("a step failure of the result is null")?;
        parts.push(format!(
            "{}: {}",
            failure.step.as_deref().unwrap_or("null"),
            failure.reason.as_deref().unwrap_or("null")
        ));
    }
    let joined = parts.join(" | ");
    Ok(Some(cut_utf16(&joined, SUMMARY_MAX_LENGTH)))
}

/// `substring(0, length)` in UTF-16 units, a cut high surrogate written as JDBC writes it, `?`.
fn cut_utf16(text: &str, length: usize) -> String {
    crate::internal::queue::truncate_to(text, length)
}

/// `PluginOutcome.of(step)`.
fn outcome_of(step: &vectispire_protocol::ReceivedStep) -> PluginOutcome {
    use vectispire_protocol::ReceivedStep;
    match step {
        ReceivedStep::Produced { plugin_id, manifest_digest, findings, signature, .. } => PluginOutcome {
            plugin_id: plugin_id.clone(),
            manifest_digest: manifest_digest.clone(),
            state: Some("produced".to_owned()),
            findings: Some(i32::try_from(findings.len()).unwrap_or(i32::MAX)),
            languages: Some(Vec::new()),
            reason: None,
            refusal: None,
            signature: signature.map(|signature| signature_name(signature).to_owned()),
        },
        ReceivedStep::NotApplicable { plugin_id, manifest_digest, languages } => PluginOutcome {
            plugin_id: plugin_id.clone(),
            manifest_digest: manifest_digest.clone(),
            state: Some("not_applicable".to_owned()),
            findings: None,
            languages: Some(languages.iter().map(|language| Some((*language).to_owned())).collect()),
            reason: None,
            refusal: None,
            signature: None,
        },
        ReceivedStep::Absent { plugin_id, manifest_digest, reason } => PluginOutcome {
            plugin_id: plugin_id.clone(),
            manifest_digest: manifest_digest.clone(),
            state: Some("absent".to_owned()),
            findings: None,
            languages: Some(Vec::new()),
            reason: reason.clone(),
            refusal: None,
            signature: None,
        },
        ReceivedStep::Refused { plugin_id, manifest_digest, refusal, reason } => PluginOutcome {
            plugin_id: plugin_id.clone(),
            manifest_digest: manifest_digest.clone(),
            state: Some("refused".to_owned()),
            findings: None,
            languages: Some(Vec::new()),
            reason: reason.clone(),
            refusal: refusal.map(|refusal| refusal_name(refusal).to_owned()),
            signature: None,
        },
    }
}

fn signature_name(signature: vectispire_protocol::Signature) -> &'static str {
    match signature {
        vectispire_protocol::Signature::Verified => "verified",
        vectispire_protocol::Signature::Waived => "waived",
        vectispire_protocol::Signature::NotRequired => "not_required",
    }
}

fn refusal_name(refusal: vectispire_protocol::Refusal) -> &'static str {
    match refusal {
        vectispire_protocol::Refusal::Unsigned => "unsigned",
        vectispire_protocol::Refusal::SignatureUnverified => "signature_unverified",
        vectispire_protocol::Refusal::RegistryAuthenticationRequired => "registry_authentication_required",
    }
}

/// `sentence`: what a scan that could not run says of it, whichever executor it was — the instant to the second,
/// since a person reads it and its nanoseconds are the clock's, not the rule's.
pub fn sentence(outcome: &Abandoned, place: &str, reason: &str) -> String {
    let attempt = format!("Attempt {} of {} could not run {place}", outcome.attempt, outcome.max_attempts);
    let next = match outcome.next {
        Next::Retry { not_before } => format!(
            "; the scan is back in the queue, not before {}: ",
            vectispire_cp_audit::iso_instant(crate::instants::offset(vectispire_domain::instant::Instant {
                epoch_second: not_before.epoch_second,
                nano: 0,
            }))
        ),
        Next::Fail { permanent: true } => ", and another attempt would meet the same refusal: ".to_owned(),
        Next::Fail { permanent: false } => ", and it was the last: ".to_owned(),
    };
    format!("{attempt}{next}{reason}")
}

fn log_abandoned(scan: i64, place: &str, done: &Abandoned) {
    if done.permanent() {
        tracing::warn!(scan, place, "A scan failed for good: the failure is not one another attempt would pass.");
    } else if !done.retried() {
        tracing::warn!(scan, place, attempts = done.attempt, "A scan failed for good after its attempts.");
    } else {
        tracing::info!(
            scan,
            place,
            attempt = done.attempt,
            max = done.max_attempts,
            "A scan could not run — back in the queue, after its wait."
        );
    }
}
