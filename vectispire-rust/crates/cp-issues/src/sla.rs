//! Remediation SLA policies, assessment, and breach detection.

use std::collections::BTreeMap;
use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use vectispire_cp_db::{Db, Visibility};
use vectispire_cp_outbox::SecurityEvents;
use vectispire_cp_settings::{Setting, Settings};
use vectispire_domain::Severity;

use crate::error::IssueError;
use crate::persistence::IssueFilters;
use crate::persistence::IssueRepository;

/// Where an issue stands against its remediation deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlaState {
    OnTime,
    DueSoon,
    Overdue,
}

impl SlaState {
    pub fn wire_name(&self) -> &'static str {
        match self {
            SlaState::OnTime => "on_time",
            SlaState::DueSoon => "due_soon",
            SlaState::Overdue => "overdue",
        }
    }
}

/// The assessment of one issue against an SLA window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub due_at: OffsetDateTime,
    pub state: SlaState,
    pub days: i64,
}

impl Assessment {
    pub fn is_overdue(&self) -> bool {
        self.state == SlaState::Overdue
    }
}

const NANOS_PER_DAY: i128 = 86_400_000_000_000;

/// How long a finding of a given severity may stay open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationSla {
    windows: BTreeMap<Severity, Duration>,
}

impl RemediationSla {
    /// Past this deadline horizon, an issue is "due soon" (7 days).
    pub const DUE_SOON: Duration = Duration::days(7);

    pub fn new(windows: BTreeMap<Severity, Duration>) -> Self {
        let mut filtered = BTreeMap::new();
        for (severity, window) in windows {
            if window.is_positive() {
                filtered.insert(severity, window);
            }
        }
        Self { windows: filtered }
    }

    pub fn default_policy() -> Self {
        let mut map = BTreeMap::new();
        map.insert(Severity::Critical, Duration::days(15));
        map.insert(Severity::High, Duration::days(30));
        map.insert(Severity::Medium, Duration::days(90));
        map.insert(Severity::Low, Duration::days(180));
        Self::new(map)
    }

    pub fn windows(&self) -> &BTreeMap<Severity, Duration> {
        &self.windows
    }

    pub fn window_for(&self, severity: Severity) -> Option<Duration> {
        self.windows.get(&severity).copied()
    }

    /// Assess where an issue stands against its deadline.
    pub fn assess(
        &self,
        severity: Severity,
        first_seen_at: OffsetDateTime,
        open: bool,
        settled: bool,
        now: OffsetDateTime,
    ) -> Option<Assessment> {
        if !open || settled {
            return None;
        }

        let window = self.window_for(severity)?;
        let due_at = first_seen_at.saturating_add(window);
        let late = now > due_at;
        // `ChronoUnit.DAYS.between(now, dueAt)`: whole days to the nanosecond, truncated toward zero. Counted in whole
        // seconds, an issue first seen at 10:00:00.2 and read at 10:00:00.7 was 30 days from due, where Java says 29.
        let days = due_at
            .unix_timestamp_nanos()
            .saturating_sub(now.unix_timestamp_nanos())
            .checked_div(NANOS_PER_DAY)
            .and_then(|days| i64::try_from(days).ok())
            .unwrap_or(0);

        let state = if late {
            SlaState::Overdue
        } else if due_at.saturating_sub(Self::DUE_SOON) <= now {
            SlaState::DueSoon
        } else {
            SlaState::OnTime
        };

        Some(Assessment { due_at, state, days })
    }

    /// Every threshold instant before which an issue of this severity is late.
    pub fn overdue_thresholds(&self, now: OffsetDateTime) -> BTreeMap<String, OffsetDateTime> {
        let mut thresholds = BTreeMap::new();
        for (severity, window) in &self.windows {
            thresholds.insert(severity.wire_name().to_owned(), now.saturating_sub(*window));
        }
        thresholds
    }
}

/// The SLA evaluation service backed by settings and the database.
#[derive(Clone)]
pub struct SlaService {
    db: Db,
    settings: Arc<Settings>,
}

impl SlaService {
    pub fn new(db: Db, settings: Arc<Settings>) -> Self {
        Self { db, settings }
    }

    /// Reads the configured policy from settings.
    pub async fn policy(&self) -> Result<RemediationSla, IssueError> {
        let critical_days = self.settings.as_int(Setting::SlaCriticalDays).await.unwrap_or(15);
        let high_days = self.settings.as_int(Setting::SlaHighDays).await.unwrap_or(30);
        let medium_days = self.settings.as_int(Setting::SlaMediumDays).await.unwrap_or(90);
        let low_days = self.settings.as_int(Setting::SlaLowDays).await.unwrap_or(180);

        let mut windows = BTreeMap::new();
        windows.insert(Severity::Critical, Duration::days(i64::from(critical_days)));
        windows.insert(Severity::High, Duration::days(i64::from(high_days)));
        windows.insert(Severity::Medium, Duration::days(i64::from(medium_days)));
        windows.insert(Severity::Low, Duration::days(i64::from(low_days)));

        Ok(RemediationSla::new(windows))
    }

    /// Returns overdue thresholds at the given instant.
    pub async fn overdue_thresholds(
        &self,
        now: OffsetDateTime,
    ) -> Result<BTreeMap<String, OffsetDateTime>, IssueError> {
        let policy = self.policy().await?;
        Ok(policy.overdue_thresholds(now))
    }

    /// Builds the overdue criteria for issues query.
    pub fn overdue(thresholds: BTreeMap<String, OffsetDateTime>, allowed: Visibility) -> IssueFilters {
        let mut filters = IssueFilters::new(allowed);
        filters.state = Some("open".to_owned());
        filters.exclude_settled = true;
        filters.overdue_before = thresholds;
        filters
    }

    /// Counts how many open issues are past their window within what the caller may see.
    pub async fn count_overdue(&self, allowed: &Visibility) -> Result<i64, IssueError> {
        let now = OffsetDateTime::now_utc();
        let thresholds = self.overdue_thresholds(now).await?;
        if thresholds.is_empty() {
            return Ok(0);
        }

        let mut tx = crate::persistence::read(&self.db).await?;
        let filters = Self::overdue(thresholds, allowed.clone());
        let count = IssueRepository::count_issues(&mut tx, &filters).await?;
        Ok(count)
    }

    /// The overdue count grouped by target (`repo:<id>` / `container:<id>`).
    pub async fn count_overdue_by_target(&self, allowed: &Visibility) -> Result<BTreeMap<String, i64>, IssueError> {
        let now = OffsetDateTime::now_utc();
        let thresholds = self.overdue_thresholds(now).await?;
        if thresholds.is_empty() {
            return Ok(BTreeMap::new());
        }

        let mut tx = crate::persistence::read(&self.db).await?;
        let filters = Self::overdue(thresholds, allowed.clone());
        let (rows, _) = IssueRepository::find_page(&mut tx, &filters, 0, 10_000).await?;

        let mut per_target = BTreeMap::new();
        for row in rows {
            let key = match (row.repo_id, row.container_id) {
                (Some(repo_id), _) => format!("repo:{repo_id}"),
                (None, Some(container_id)) => format!("container:{container_id}"),
                (None, None) => continue,
            };
            let entry = per_target.entry(key).or_insert(0i64);
            *entry = entry.saturating_add(1);
        }
        Ok(per_target)
    }
}

/// Emits signals when remediation SLA deadlines pass.
pub struct SlaBreachSignals {
    db: Db,
    sla: Arc<SlaService>,
    events: Arc<dyn SecurityEvents>,
}

impl SlaBreachSignals {
    pub const LOOKBACK: Duration = Duration::days(7);
    pub const BATCH: usize = 200;

    pub fn new(db: Db, sla: Arc<SlaService>, events: Arc<dyn SecurityEvents>) -> Self {
        Self { db, sla, events }
    }

    /// Scans for deadlines passed since the last turn and marks them signalled.
    pub async fn signal_crossings(&self) -> Result<usize, IssueError> {
        let now = OffsetDateTime::now_utc();
        let policy = self.sla.policy().await?;

        let mut total_signalled = 0usize;
        for (severity, window) in policy.windows() {
            let count = self.signal_severity(*severity, *window, now).await?;
            total_signalled = total_signalled.saturating_add(count);
        }
        Ok(total_signalled)
    }

    async fn signal_severity(
        &self,
        severity: Severity,
        window: Duration,
        now: OffsetDateTime,
    ) -> Result<usize, IssueError> {
        let before = now.saturating_sub(window);
        let since = before.saturating_sub(Self::LOOKBACK);
        let mut signalled = 0usize;
        let mut after_id = 0i64;
        let settled: Vec<String> =
            crate::triage::TriageStatus::settled_wire_names().iter().map(|&s| s.to_string()).collect();

        loop {
            let mut tx = crate::persistence::write(&self.db).await?;
            let breaches = IssueRepository::find_unsignalled_breaches(
                &mut tx,
                "open",
                severity.wire_name(),
                before,
                since,
                &settled,
                after_id,
                Self::BATCH as i64,
            )
            .await?;

            if breaches.is_empty() {
                break;
            }

            // Each event queued in the batch's transaction, with the mark that keeps it from being raised again: the
            // two commit together, or the next turn finds the issue unsignalled and raises it then. The deadlines
            // were marked here and announced nowhere until the SIEM was composed.
            for breach in &breaches {
                let event = crate::signals::sla_breach(
                    crate::signals::Signalled {
                        id: breach.id,
                        identifier: &breach.identifier,
                        file_path: breach.file_path.as_deref(),
                        package_name: breach.package_name.as_deref(),
                        repo_id: breach.repo_id,
                        container_id: breach.container_id,
                        first_seen_at: breach.first_seen_at,
                    },
                    severity,
                    window,
                    breach.first_seen_at.saturating_add(window),
                )
                .map_err(|refused| IssueError::Store(refused.0))?;
                self.events.raise(&mut tx, &event).await.map_err(|failed| IssueError::Store(failed.to_string()))?;
            }
            let ids: Vec<i64> = breaches.iter().map(|b| b.id).collect();
            IssueRepository::mark_sla_breach_signalled(&mut tx, &ids, now).await?;
            crate::persistence::commit(tx).await?;

            signalled = signalled.saturating_add(ids.len());
            if ids.len() < Self::BATCH {
                break;
            }
            if let Some(last_id) = ids.last() {
                after_id = *last_id;
            } else {
                break;
            }
        }

        Ok(signalled)
    }
}

opaque_debug!(SlaService, SlaBreachSignals);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn days(first_seen: OffsetDateTime, now: OffsetDateTime) -> i64 {
        RemediationSla::default_policy().assess(Severity::High, first_seen, true, false, now).unwrap().days
    }

    #[test]
    fn the_days_to_due_are_counted_to_the_nanosecond_as_chrono_unit_counts_them() {
        let first_seen = OffsetDateTime::from_unix_timestamp_nanos(1_793_103_941_200_000_000).unwrap();
        // Half a second later, in the same second: 29 days and some hours left, not 30.
        assert_eq!(days(first_seen, first_seen + Duration::milliseconds(500)), 29);
        assert_eq!(days(first_seen, first_seen), 30);
        // Late by less than a day is 0, by a day and a half -1: truncated toward zero, as Java's between.
        assert_eq!(days(first_seen, first_seen + Duration::days(30) + Duration::hours(1)), 0);
        assert_eq!(days(first_seen, first_seen + Duration::days(31) + Duration::hours(12)), -1);
    }
}
