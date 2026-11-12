//! A remote agent's loop: claim, run, hand back — up to the agent's limit at once — `AgentLoop` and
//! `Slots`.
//!
//! Apart from the protocol and the runner for the same reason as on the Java side: this file carries
//! **decisions** — when to give up, when to stay quiet, what to do with a lost lease, how many scans to
//! hold — and they are testable with a stub control plane and no Docker.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::task::JoinSet;
use vectispire_domain::FailureKind;
use vectispire_domain::failure::Classified;
use vectispire_domain::repository_url;
use vectispire_domain::secret::Secret;
use vectispire_protocol::{
    AgentClient, AssignedTask, FailureReported, ProtocolError, ScanArtifacts, ScanTask, Target, concurrency,
    failure_reason,
};

pub use vectispire_runner::ExecutionFailure;

/// What runs a claimed scan — the shared runner on the Java side (`ScanRunner::run`).
pub trait Execute: Send + Sync + 'static {
    fn execute(&self, task: ScanTask) -> impl Future<Output = Result<ScanArtifacts, ExecutionFailure>> + Send;
}

/// What became of the scans one call handled — `AgentLoop.Result`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Handed back.
    pub completed: u32,
    /// Not run, or not delivered.
    pub failed: u32,
    /// The lease was lost: the result was not sent.
    pub abandoned: u32,
}

impl Outcome {
    const COMPLETED: Outcome = Outcome { completed: 1, failed: 0, abandoned: 0 };
    const FAILED: Outcome = Outcome { completed: 0, failed: 1, abandoned: 0 };
    const ABANDONED: Outcome = Outcome { completed: 0, failed: 0, abandoned: 1 };
}

/// The loop's timings and the process's own secrets.
#[derive(Debug, Clone)]
pub struct Settings {
    pub claim_wait: Duration,
    pub retry_delay: Duration,
    pub heartbeat: Duration,
    /// The API key and the signing key: scrubbed from every reason that leaves, beside the task's own.
    pub secrets: Vec<Secret>,
}

/// The scans an agent may hold at once — `Slots`: a limit that changes while scans run.
///
/// A semaphore would not do: its permits cannot be taken back when the control plane lowers the limit
/// while every slot is busy. Here a lower limit simply holds the next claim until enough scans finish.
#[derive(Debug)]
pub struct Slots {
    state: Mutex<SlotState>,
    changed: Notify,
}

#[derive(Debug)]
struct SlotState {
    limit: u32,
    busy: u32,
    closed: bool,
}

impl Slots {
    pub fn new(limit: u32) -> Slots {
        Slots {
            state: Mutex::new(SlotState {
                limit: concurrency::effective(Some(i64::from(limit))),
                busy: 0,
                closed: false,
            }),
            changed: Notify::new(),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits for a free slot and takes it; `false` once closed — the loop is stopping.
    pub async fn acquire(&self) -> bool {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.state();
                if state.closed {
                    return false;
                }
                if state.busy < state.limit {
                    state.busy += 1;
                    return true;
                }
            }
            notified.await;
        }
    }

    pub fn release(&self) {
        let mut state = self.state();
        state.busy = state.busy.saturating_sub(1);
        drop(state);
        self.changed.notify_waiters();
    }

    pub fn resize(&self, requested: u32) {
        self.state().limit = concurrency::effective(Some(i64::from(requested)));
        self.changed.notify_waiters();
    }

    pub fn close(&self) {
        self.state().closed = true;
        self.changed.notify_waiters();
    }

    pub fn limit(&self) -> u32 {
        self.state().limit
    }

    #[cfg(test)]
    pub fn busy(&self) -> u32 {
        self.state().busy
    }
}

/// The loop. Cheap to share: [`AgentLoop::stop`] is called from the signal handler's task while
/// [`AgentLoop::serve`] runs.
#[derive(Debug)]
pub struct AgentLoop<E> {
    client: Arc<AgentClient>,
    execute: Arc<E>,
    settings: Settings,
    slots: Arc<Slots>,
    stopping: AtomicBool,
    stopped: Notify,
}

impl<E: Execute> AgentLoop<E> {
    /// `max_concurrent` is the limit the hello announced; each claim's answer may change it.
    pub fn new(client: Arc<AgentClient>, execute: Arc<E>, settings: Settings, max_concurrent: u32) -> AgentLoop<E> {
        AgentLoop {
            client,
            execute,
            settings,
            slots: Arc::new(Slots::new(max_concurrent)),
            stopping: AtomicBool::new(false),
            stopped: Notify::new(),
        }
    }

    #[cfg(test)]
    pub fn slots(&self) -> &Slots {
        &self.slots
    }

    /// Claims and runs scans until [`AgentLoop::stop`] is called, at most the limit at a time.
    ///
    /// **One claim in flight, never more.** A free slot is taken before the poll and given back if the
    /// poll brings nothing, so the agent never asks for work it has no room for — and a full agent does
    /// not poll at all.
    ///
    /// **Returns once every scan it started has been handed back**, a fatal error included — see
    /// [`AgentLoop::stop`]. A claim answered after the stop was requested is run too: the scan is this
    /// agent's from that moment, and dropping it would hold the row until its lease lapsed.
    ///
    /// The error is a refused key or a contract gap: neither is fixed by looping.
    pub async fn serve(self: &Arc<Self>) -> Result<(), ProtocolError> {
        let mut running = JoinSet::new();
        let mut fatal = None;
        while !self.stopping.load(Ordering::SeqCst) {
            if !self.slots.acquire().await {
                break;
            }
            match self.claim().await {
                Err(error) => {
                    self.slots.release();
                    fatal = Some(error);
                    break;
                }
                Ok(None) => self.slots.release(),
                Ok(Some(assigned)) => {
                    let this = self.clone();
                    running.spawn(async move {
                        let outcome = this.run(assigned).await;
                        this.slots.release();
                        outcome
                    });
                }
            }
            while running.try_join_next().is_some() {}
        }
        while running.join_next().await.is_some() {}
        fatal.map_or(Ok(()), Err)
    }

    /// Asks [`AgentLoop::serve`] to stop claiming. Running scans are left to finish and hand back.
    ///
    /// **Waiting, not abandoning, because of what abandoning costs.** The protocol has no call to give a
    /// scan back unrun: an abandoned scan keeps its lease until it lapses — twenty minutes by default —
    /// then goes back to the queue having used one of its attempts, and every minute of work done is
    /// thrown away. Waiting costs the orchestrator's grace period, which is the operator's to set.
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        self.slots.close();
        self.stopped.notify_waiters();
    }

    /// One turn: at most one scan, run here — the same claim-run-hand-back without the concurrency, for a
    /// caller that wants one answer (the tests'; the binary serves).
    #[cfg(test)]
    pub async fn run_once(&self) -> Result<Outcome, ProtocolError> {
        match self.claim().await? {
            None => Ok(Outcome::default()),
            Some(assigned) => Ok(self.run(assigned).await),
        }
    }

    /// Asks for a task, and takes the limit the answer carries.
    ///
    /// A refused key or a contract gap is returned: a loop that logged them as a failed claim would retry
    /// a revoked key every ten seconds for ever. Anything else costs a turn, not a scan: the control
    /// plane keeps the row queued.
    async fn claim(&self) -> Result<Option<AssignedTask>, ProtocolError> {
        let claim = match self.client.claim(self.settings.claim_wait).await {
            Ok(claim) => claim,
            Err(fatal) if fatal.is_fatal() => return Err(fatal),
            Err(unusable @ ProtocolError::UnusableTask { .. }) => {
                // Claimed on the control plane's side, unusable on this one: a scan this agent holds, so
                // it is reported rather than left to its lease.
                let kind = unusable.failure_kind();
                if let ProtocolError::UnusableTask { assigned, message } = unusable {
                    self.report_failure(&assigned, &message, kind).await;
                }
                return Ok(None);
            }
            Err(failed) => {
                tracing::warn!("Could not claim: {failed}");
                self.pause(self.settings.retry_delay).await;
                return Ok(None);
            }
        };
        if let Some(limit) = claim.max_concurrent {
            let current = self.slots.limit();
            if limit != current {
                tracing::info!("Concurrent scans: {limit} (was {current}).");
                self.slots.resize(limit);
            }
        }
        Ok(claim.task)
    }

    /// A pause a stop cuts short.
    async fn pause(&self, duration: Duration) {
        let stopped = self.stopped.notified();
        tokio::pin!(stopped);
        stopped.as_mut().enable();
        if self.stopping.load(Ordering::SeqCst) {
            return;
        }
        tokio::select! {
            () = tokio::time::sleep(duration) => {}
            () = stopped => {}
        }
    }

    /// Runs one claimed scan and hands its result back. **Each scan reports on its own**: one whose
    /// upload fails, or whose lease was taken over, says so for itself and costs the others nothing.
    async fn run(&self, assigned: AssignedTask) -> Outcome {
        let scan = assigned.scan_id;
        tracing::info!("Scan {scan}: {}.", describe(&assigned.task));

        let lost = Arc::new(AtomicBool::new(false));
        let beating = self.start_heartbeat(scan, lost.clone());
        let executed = self.execute.execute(assigned.task.clone()).await;
        beating.abort();

        let artifacts = match executed {
            Ok(artifacts) => artifacts,
            Err(failure) => {
                // **No result is handed back.** An empty result after a failed run would resolve the
                // whole backlog of the types it did not look at (decision 0007). A failure report
                // resolves nothing: it spends the attempt the lapsing lease would have spent, now, with
                // the reason.
                self.report_failure(&assigned, &failure.message, failure.kind).await;
                return Outcome::FAILED;
            }
        };
        if lost.load(Ordering::SeqCst) {
            // Handing the result back would overwrite the successor's, which is more recent than ours.
            tracing::warn!("Scan {scan}: lease taken over during execution, result discarded.");
            return Outcome::ABANDONED;
        }
        match self.client.submit(scan, &artifacts).await {
            Ok(true) => {
                tracing::info!("Scan {scan} submitted.");
                Outcome::COMPLETED
            }
            Ok(false) => {
                tracing::warn!("Scan {scan}: result discarded, the lease was no longer ours.");
                Outcome::ABANDONED
            }
            Err(failed) => {
                // The work is done but could not be handed back. Retrying the upload would keep the agent
                // busy on a result whose lease is lapsing anyway.
                tracing::warn!("Scan {scan}: result not delivered ({failed}).");
                Outcome::FAILED
            }
        }
    }

    /// The sign of life, running beside the execution: what tells "slow" from "dead". A missed beat is
    /// not a lost lease — the network hiccups, and the lease lasts several times the interval.
    fn start_heartbeat(&self, scan: i64, lost: Arc<AtomicBool>) -> tokio::task::JoinHandle<()> {
        let client = self.client.clone();
        let period = self.settings.heartbeat;
        tokio::spawn(async move {
            let mut beats = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            loop {
                beats.tick().await;
                match client.heartbeat(scan).await {
                    Ok(true) => {}
                    Ok(false) => lost.store(true, Ordering::SeqCst),
                    Err(missed) => tracing::warn!("Missed heartbeat for scan {scan}: {missed}"),
                }
            }
        })
    }

    /// Tells the control plane a claimed scan could not run, or says in the log why it could not be told.
    ///
    /// **Scrubbed here of every secret this process holds**, by value, before the text leaves — the
    /// same scrubbed text is what the log shows. Whatever the answer, nothing more is done with the scan.
    async fn report_failure(&self, assigned: &AssignedTask, raw: &str, kind: FailureKind) {
        let scan = assigned.scan_id;
        let secrets = self.secrets_of(&assigned.task);
        let reason = failure_reason::scrub(raw, secrets.iter().copied());
        match self.client.report_failure(assigned, &reason, kind).await {
            Ok(FailureReported::Retried) => tracing::warn!(
                "Scan {scan} could not run, reported; it is back in the queue and waits before its next attempt: {reason}"
            ),
            Ok(FailureReported::Failed) if kind == FailureKind::Permanent => tracing::warn!(
                "Scan {scan} could not run, reported; another attempt would fail the same way, the scan failed: {reason}"
            ),
            Ok(FailureReported::Failed) => {
                tracing::warn!(
                    "Scan {scan} could not run, reported; it was its last attempt, the scan failed: {reason}"
                )
            }
            Ok(FailureReported::NotYours) => {
                tracing::warn!("Scan {scan} could not run, and was no longer ours to report: {reason}")
            }
            Ok(FailureReported::NotSupported) => tracing::warn!(
                "Scan {scan} abandoned: {reason} — the control plane takes no failure report (older than this agent); \
                 the scan goes back to the queue when its lease lapses."
            ),
            Err(unreported) => tracing::warn!(
                "Scan {scan} abandoned: {reason} — the failure could not be reported ({}); the scan goes back to the \
                 queue when its lease lapses.",
                failure_reason::scrub(&unreported.to_string(), secrets.iter().copied())
            ),
        }
    }

    fn secrets_of<'a>(&'a self, task: &'a ScanTask) -> Vec<Option<&'a str>> {
        self.settings
            .secrets
            .iter()
            .chain(task.secrets())
            .map(|secret| Some(secret.expose()))
            .chain([Some(self.client.api_key().expose())])
            .collect()
    }
}

/// How a scan is named in the log — the URL without its credentials, or the image.
fn describe(task: &ScanTask) -> String {
    match &task.target {
        Target::Repository(repository) => {
            format!("{} ({})", repository_url::redact(&repository.url), repository.branch.as_deref().unwrap_or("null"))
        }
        Target::Image(image) => image.reference.format(),
    }
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod tests;
