//! The gauges of the queue and of the agents — Java 1.0's `PlatformMetrics` and `AgentMetrics` — and the two
//! maintenance tasks that read their figures, `SCAN_METRICS` and `AGENT_METRICS`.
//!
//! **A gauge reads a snapshot, never the database.** Counting at every scrape runs the counts on the scraping
//! request with a connection from the pool, and the pool is what is exhausted during the incident the gauges exist
//! for: the scrape then waits, the scraper gives up, and the series vanish when they are needed most. The counts run
//! once per scheduling tick and a scrape reads what the last one found. `vectispire.metrics.snapshot.age` says how
//! old the figures are, so a tick that stopped reads as stale rather than as a quiet queue; before the first tick
//! every gauge reads NaN — not measured yet, which a zero would hide. A tick that fails keeps the previous snapshot,
//! and its age says so.
//!
//! **Composed here, not in the modules**: the figures come from three of them (scanning, outbox, agents), and the
//! registry is `cp-runtime`'s, which no module crate depends on. The names, descriptions and tags are Java's — the
//! ones dashboards were written against — and **no tag names a repository, a target, a user or an agent**: every tag
//! takes two values.

use std::sync::{Arc, RwLock};

use time::OffsetDateTime;
use vectispire_cp_agents::AgentAdministrationService;
use vectispire_cp_maintenance::{MaintenanceTask, Sequence, TaskRun};
use vectispire_cp_outbox::Outbox;
use vectispire_cp_runtime::metrics::Metrics;
use vectispire_cp_scanning::ScanQueue;

const SECONDS: Option<&str> = Some("seconds");

/// How many scans of one kind wait, and when the oldest was queued.
#[derive(Debug, Clone, Copy)]
struct Waiting {
    count: i64,
    oldest: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Copy)]
struct ScanSnapshot {
    at: OffsetDateTime,
    repositories: Waiting,
    containers: Waiting,
    running: i64,
    outbox_pending: i64,
}

#[derive(Debug, Clone, Copy)]
struct AgentSnapshot {
    at: OffsetDateTime,
    enabled: usize,
    online: usize,
    least_recently_seen: Option<OffsetDateTime>,
    unserved: i64,
}

/// Seconds from `since` to now; zero for none, and never negative — `ageInSeconds`. Computed at the scrape, so the
/// oldest waiting scan keeps ageing between two ticks instead of standing still for a minute.
fn age(since: Option<OffsetDateTime>) -> f64 {
    since.map_or(0.0, |since| {
        let nanos = OffsetDateTime::now_utc().unix_timestamp_nanos().checked_sub(since.unix_timestamp_nanos());
        (nanos.unwrap_or(0) as f64 / 1e9).max(0.0)
    })
}

/// What the gauge reads from the last snapshot, or NaN before the first one.
fn read<S: Copy>(snapshot: &RwLock<Option<S>>, figure: impl Fn(S) -> f64) -> f64 {
    snapshot.read().ok().and_then(|current| *current).map_or(f64::NAN, figure)
}

/// The queue's gauges: scans waiting per kind and the oldest one's age, scans running, notifications not sent.
#[derive(Debug)]
pub struct ScanGauges {
    queue: Arc<ScanQueue>,
    outbox: Arc<Outbox>,
    snapshot: Arc<RwLock<Option<ScanSnapshot>>>,
}

impl ScanGauges {
    #[must_use]
    pub fn new(queue: Arc<ScanQueue>, outbox: Arc<Outbox>) -> ScanGauges {
        ScanGauges { queue, outbox, snapshot: Arc::new(RwLock::new(None)) }
    }

    /// Reads the figures — the tick's work. A failure keeps the previous snapshot.
    pub async fn refresh(&self) -> Result<(), vectispire_cp_maintenance::TaskError> {
        let (count, oldest) = self.queue.waiting_of_kind(true).await?;
        let repositories = Waiting { count, oldest };
        let (count, oldest) = self.queue.waiting_of_kind(false).await?;
        let containers = Waiting { count, oldest };
        let running = self.queue.count_running().await?;
        // Every message not sent, abandoned ones included — the relay's own count.
        let outbox_pending = self
            .outbox
            .counts()
            .await?
            .iter()
            .filter(|(status, _)| !status.eq_ignore_ascii_case("SENT"))
            .map(|(_, n)| *n)
            .sum();
        let taken = ScanSnapshot { at: OffsetDateTime::now_utc(), repositories, containers, running, outbox_pending };
        if let Ok(mut current) = self.snapshot.write() {
            *current = Some(taken);
        }
        Ok(())
    }

    /// Registers the gauges — once, at start, before the first tick: they read NaN until it.
    pub fn register(&self, metrics: &Metrics) {
        for (kind, pick) in [("repository", true), ("container", false)] {
            let which = move |s: ScanSnapshot| if pick { s.repositories } else { s.containers };
            let snapshot = self.snapshot.clone();
            // `queued` kept its name when it gained the tag: summed over `kind` it is the number it was.
            metrics.gauge_with(
                "vectispire.scans.queued",
                "Scans waiting for a worker or an agent to claim them, retry delays included",
                &[("kind", kind)],
                None,
                move || read(&snapshot, |s| which(s).count as f64),
            );
            let snapshot = self.snapshot.clone();
            metrics.gauge_with(
                "vectispire.scans.queued.oldest.age",
                "How long the oldest waiting scan has waited since it was queued; zero when none waits",
                &[("kind", kind)],
                SECONDS,
                move || read(&snapshot, |s| age(which(s).oldest)),
            );
        }
        let snapshot = self.snapshot.clone();
        metrics.gauge_with("vectispire.scans.running", "Scans claimed and not yet reported", &[], None, move || {
            read(&snapshot, |s| s.running as f64)
        });
        let snapshot = self.snapshot.clone();
        metrics.gauge_with(
            "vectispire.outbox.pending",
            "Notifications accepted but not yet delivered",
            &[],
            None,
            move || read(&snapshot, |s| s.outbox_pending as f64),
        );
        let snapshot = self.snapshot.clone();
        metrics.gauge_with(
            "vectispire.metrics.snapshot.age",
            "How old the figures the database gauges report are; it grows when the tick stops",
            &[("source", "scans")],
            SECONDS,
            move || read(&snapshot, |s| age(Some(s.at))),
        );
    }
}

/// The agents' gauges: enabled, online, the least recently seen one's silence, and the scans no executor able to be
/// handed their credential can take.
#[derive(Debug)]
pub struct AgentGauges {
    admin: Arc<AgentAdministrationService>,
    snapshot: Arc<RwLock<Option<AgentSnapshot>>>,
}

impl AgentGauges {
    #[must_use]
    pub fn new(admin: Arc<AgentAdministrationService>) -> AgentGauges {
        AgentGauges { admin, snapshot: Arc::new(RwLock::new(None)) }
    }

    /// Reads the figures — the tick's work. A failure keeps the previous snapshot.
    pub async fn refresh(&self) -> Result<(), vectispire_cp_maintenance::TaskError> {
        let at = OffsetDateTime::now_utc();
        let figures = self.admin.gauge_figures(at).await?;
        let taken = AgentSnapshot {
            at,
            enabled: figures.enabled,
            online: figures.online,
            least_recently_seen: figures.least_recently_seen,
            unserved: figures.unserved,
        };
        if let Ok(mut current) = self.snapshot.write() {
            *current = Some(taken);
        }
        Ok(())
    }

    /// Registers the gauges — once, at start.
    pub fn register(&self, metrics: &Metrics) {
        let snapshot = self.snapshot.clone();
        metrics.gauge_with(
            "vectispire.agents.enabled",
            "Remote agents an operator has enabled",
            &[],
            None,
            move || read(&snapshot, |s| s.enabled as f64),
        );
        let snapshot = self.snapshot.clone();
        metrics.gauge_with(
            "vectispire.agents.online",
            "Enabled agents heard from within the last two minutes, as the agents screen counts them",
            &[],
            None,
            move || read(&snapshot, |s| s.online as f64),
        );
        // The least recently seen, not an average: one agent that stopped polling is the case to alert on, and an
        // average over a healthy fleet hides it.
        let snapshot = self.snapshot.clone();
        metrics.gauge_with(
            "vectispire.agents.last.seen.age",
            "How long the least recently seen enabled agent has been silent — since its creation if it never polled; \
             zero when none is enabled",
            &[],
            SECONDS,
            move || read(&snapshot, |s| age(s.least_recently_seen)),
        );
        // Beside the queue's gauge rather than inside it: zero is the healthy value, anything else waits on an operator.
        let snapshot = self.snapshot.clone();
        metrics.gauge_with(
            "vectispire.scans.credential.unserved",
            "Waiting scans needing a credential that no executor able to be handed it can take",
            &[],
            None,
            move || read(&snapshot, |s| s.unserved as f64),
        );
        let snapshot = self.snapshot.clone();
        metrics.gauge_with(
            "vectispire.metrics.snapshot.age",
            "How old the figures the database gauges report are; it grows when the tick stops",
            &[("source", "agents")],
            SECONDS,
            move || read(&snapshot, |s| age(Some(s.at))),
        );
    }
}

/// `ScanMetricsTask`: the queue's gauges, read on the scheduling turn. Every instance runs it — each instance's gauges
/// are its own.
#[derive(Debug)]
pub struct ScanMetricsTask(pub Arc<ScanGauges>);

impl MaintenanceTask for ScanMetricsTask {
    fn sequence(&self) -> Sequence {
        Sequence::ScanMetrics
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(self.0.refresh())
    }
}

/// `AgentMetricsTask`: the agents' gauges, read on the scheduling turn.
#[derive(Debug)]
pub struct AgentMetricsTask(pub Arc<AgentGauges>);

impl MaintenanceTask for AgentMetricsTask {
    fn sequence(&self) -> Sequence {
        Sequence::AgentMetrics
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(self.0.refresh())
    }
}

/// Both sets of gauges: built before the maintenance composition, which runs their tasks, and registered on the
/// application's registry once it exists.
#[derive(Debug, Clone)]
pub struct Gauges {
    pub scans: Arc<ScanGauges>,
    pub agents: Arc<AgentGauges>,
}

impl Gauges {
    #[must_use]
    pub fn new(queue: Arc<ScanQueue>, outbox: Arc<Outbox>, admin: Arc<AgentAdministrationService>) -> Gauges {
        Gauges { scans: Arc::new(ScanGauges::new(queue, outbox)), agents: Arc::new(AgentGauges::new(admin)) }
    }

    /// `SCAN_METRICS` and `AGENT_METRICS`.
    #[must_use]
    pub fn tasks(&self) -> Vec<Arc<dyn MaintenanceTask>> {
        vec![Arc::new(ScanMetricsTask(self.scans.clone())), Arc::new(AgentMetricsTask(self.agents.clone()))]
    }

    pub fn register(&self, metrics: &Metrics) {
        self.scans.register(metrics);
        self.agents.register(metrics);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gauge_reads_nan_until_the_first_tick_and_an_age_is_never_negative() {
        let none: RwLock<Option<ScanSnapshot>> = RwLock::new(None);
        assert!(read(&none, |s| s.running as f64).is_nan());
        assert!((age(None) - 0.0).abs() < f64::EPSILON);
        let future = OffsetDateTime::now_utc() + time::Duration::hours(1);
        assert!((age(Some(future)) - 0.0).abs() < f64::EPSILON);
        let past = OffsetDateTime::now_utc() - time::Duration::seconds(90);
        assert!(age(Some(past)) >= 90.0);
    }
}
