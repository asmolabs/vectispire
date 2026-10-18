//! The periodic rescan — `SchedulerService`: **the loop that gives the rest of the product its point**, in a tool whose
//! premise is that new vulnerabilities appear in code that has not changed.
//!
//! **A scheduled scan and a manual one are indistinguishable downstream**: both put a row in the queue, the same worker
//! claims it, the same ingestion reads it. **The target is stamped before it is queued**, in the same transaction:
//! stamping after would re-trigger a target on every tick while its scan outlasts the interval. **Leader-only**, through
//! `t_leader_lease`: stamping protects against one process ticking twice, not against two processes ticking together.

use time::OffsetDateTime;
use vectispire_cp_db::{ScanTarget, Tx};
use vectispire_cp_targets::views::{ContainerView, RepositoryView};
use vectispire_domain::cron::crontab;
use vectispire_domain::schedules::{self, Schedulable};

use crate::Scanning;
use crate::instants::instant;
use crate::persistence::{self, NewScan, StoreError};
use crate::trigger::IMAGE_BRANCH;

/// What "already under way" means to a round: a scan waiting, or one running — under a weekly default a slow scan
/// can still run when the round comes, and the round would only queue the same examination behind it.
const IN_FLIGHT: [&str; 2] = ["pending", "scanning"];

impl Scanning {
    /// One tick at the clock's instant; how many scans were queued.
    pub async fn schedule_once(&self) -> usize {
        self.schedule_at(self.clock.now()).await
    }

    /// One tick at `at` — **the same instant as the due check and the lease**: two clocks in one tick, one deciding who
    /// writes and the other what, would agree by chance.
    pub async fn schedule_at(&self, at: OffsetDateTime) -> usize {
        if !self.hold_leadership(at).await {
            return 0;
        }
        // Read once per tick: a default changed mid-tick must not judge half the estate by each value.
        let default_minutes = match self.settings.as_int(vectispire_cp_settings::Setting::ScanDefaultIntervalDays).await
        {
            Ok(days) => i64::from(days).saturating_mul(24 * 60),
            Err(failure) => {
                tracing::warn!(error = %failure, "Scheduler: the default interval could not be read — tick skipped.");
                return 0;
            }
        };
        let now = instant(at);
        let mut queued: usize = 0;
        match self.targets.catalog_repositories().await {
            Ok(repositories) => {
                for repository in &repositories {
                    if due_repository(repository, default_minutes, now) {
                        queued = queued.saturating_add(self.queue_repository(repository, at).await);
                    }
                }
            }
            Err(failure) => tracing::error!(error = %failure, "Scheduler: the repositories could not be read."),
        }
        match self.targets.catalog_containers().await {
            Ok(containers) => {
                for container in &containers {
                    if due_container(container, default_minutes, now) {
                        queued = queued.saturating_add(self.queue_container(container, at).await);
                    }
                }
            }
            Err(failure) => tracing::error!(error = %failure, "Scheduler: the images could not be read."),
        }
        if queued > 0 {
            tracing::info!(queued, "Scheduler: scan(s) queued.");
        }
        queued
    }

    /// Takes or renews the lease, and **fails closed**: an instance that cannot reach the lease table is not entitled
    /// to assume it is alone. A skipped tick costs a minute; a wrong belief costs a duplicate scan of every due target.
    async fn hold_leadership(&self, at: OffsetDateTime) -> bool {
        match self.election.acquire(crate::internal::leader::JOB_SCHEDULER, self.election.instance(), at).await {
            Ok(held) => held,
            Err(failure) => {
                tracing::warn!(error = %failure, "Scheduling lease unreachable — tick skipped.");
                false
            }
        }
    }

    async fn queue_repository(&self, repository: &RepositoryView, at: OffsetDateTime) -> usize {
        let scan = NewScan {
            status: "pending".to_owned(),
            created_at: at,
            repo_id: Some(repository.id),
            container_id: None,
            branch: repository.branch.clone(),
            sub_path: repository.sub_path.clone(),
            required_agent_label: repository.required_agent_label.clone(),
            not_before: None,
        };
        self.queue_target(ScanTarget::Repository(repository.id), scan, at).await
    }

    async fn queue_container(&self, container: &ContainerView, at: OffsetDateTime) -> usize {
        let scan = NewScan {
            status: "pending".to_owned(),
            created_at: at,
            repo_id: None,
            container_id: Some(container.id),
            branch: IMAGE_BRANCH.to_owned(),
            sub_path: None,
            required_agent_label: container.required_agent_label.clone(),
            not_before: None,
        };
        self.queue_target(ScanTarget::Container(container.id), scan, at).await
    }

    /// Stamped first — including when a scan is already under way, or a target whose scan drags is reconsidered on
    /// every tick — then queued unless one is waiting or running. **One failing target does not take the others with
    /// it**: the next tick sees it again.
    async fn queue_target(&self, target: ScanTarget, scan: NewScan, at: OffsetDateTime) -> usize {
        let outcome = async {
            let mut tx = persistence::write(&self.db).await?;
            let done = self.stamp_and_queue(&mut tx, target, &scan, at).await;
            match done {
                Ok(queued) => {
                    tx.commit().await.map_err(StoreError::from)?;
                    Ok(queued)
                }
                Err(failure) => {
                    let _ = tx.rollback().await;
                    Err(failure)
                }
            }
        }
        .await;
        outcome.unwrap_or_else(|failure: StoreError| {
            tracing::error!(?target, error = %failure, "Could not queue a scheduled scan.");
            0
        })
    }

    async fn stamp_and_queue(
        &self,
        tx: &mut Tx,
        target: ScanTarget,
        scan: &NewScan,
        at: OffsetDateTime,
    ) -> Result<usize, StoreError> {
        self.targets.stamp_scheduled(tx, target, at).await.map_err(|failure| StoreError(Box::new(failure)))?;
        let under_way = match target {
            ScanTarget::Repository(id) => persistence::count_in_flight_of_repository(tx, IN_FLIGHT, id).await?,
            ScanTarget::Container(id) => persistence::count_in_flight_of_container(tx, IN_FLIGHT, id).await?,
        };
        if under_way > 0 {
            return Ok(0);
        }
        persistence::insert_scan(tx, scan).await?;
        Ok(1)
    }
}

/// `Schedules.isDue(TargetSchedules.of(repository), …)`.
fn due_repository(repository: &RepositoryView, default_minutes: i64, now: vectispire_domain::instant::Instant) -> bool {
    let cron = crontab::parse(repository.scan_cron.as_deref());
    schedules::is_due(
        &Schedulable {
            target: vectispire_domain::ScanTarget::Repository(repository.id),
            manual_only: repository.scan_manual_only,
            cron: &cron,
            interval_minutes: repository.scan_interval_minutes,
            last_scheduled_at: repository.last_scheduled_scan_at.map(instant),
        },
        default_minutes,
        now,
    )
}

fn due_container(container: &ContainerView, default_minutes: i64, now: vectispire_domain::instant::Instant) -> bool {
    let cron = crontab::parse(container.scan_cron.as_deref());
    schedules::is_due(
        &Schedulable {
            target: vectispire_domain::ScanTarget::Container(container.id),
            manual_only: container.scan_manual_only,
            cron: &cron,
            interval_minutes: container.scan_interval_minutes,
            last_scheduled_at: container.last_scheduled_scan_at.map(instant),
        },
        default_minutes,
        now,
    )
}
