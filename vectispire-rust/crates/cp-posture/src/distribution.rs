//! `RemediationDistributionService`: how long resolutions took against the SLA, per severity, over a window — the share
//! within the deadline, the median and the ninetieth percentile — and the open backlog's lateness and oldest item.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Serialize;
use time::Duration;
use vectispire_cp_db::Visibility;
use vectispire_cp_issues::{IssueCatalog, SlaService};
use vectispire_cp_targets::Clock;
use vectispire_domain::Severity;

use crate::arithmetic;
use crate::dashboard::every_issue;
use crate::error::PostureError;
use crate::remediation::{BySeverity, Open, RemediationDistribution, Resolved};

pub const DEFAULT_WINDOW_DAYS: i32 = 90;
pub const MAX_WINDOW_DAYS: i32 = 365;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BySeverityView {
    pub severity: &'static str,
    pub window_days: i32,
    pub within_sla: i64,
    pub late: i64,
    pub percentage_within_sla: Option<f64>,
    pub median_days: Option<f64>,
    pub ninetieth_days: Option<f64>,
    pub open_overdue: i64,
    pub oldest_open_days: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationDistributionView {
    pub window_days: i32,
    pub by_severity: Vec<BySeverityView>,
    pub oldest_open_days: Option<i64>,
    pub oldest_open_severity: Option<&'static str>,
}

impl RemediationDistributionView {
    pub fn of(distribution: &RemediationDistribution) -> RemediationDistributionView {
        RemediationDistributionView {
            window_days: distribution.window_days,
            by_severity: distribution.by_severity.iter().map(Self::line).collect(),
            oldest_open_days: distribution.oldest_open_days,
            oldest_open_severity: distribution.oldest_open_severity.map(Severity::wire_name),
        }
    }

    fn line(row: &BySeverity) -> BySeverityView {
        BySeverityView {
            severity: row.severity.wire_name(),
            window_days: row.window_days,
            within_sla: row.within_sla,
            late: row.late,
            percentage_within_sla: row.percentage_within_sla,
            median_days: row.median_days,
            ninetieth_days: row.ninetieth_days,
            open_overdue: row.open_overdue,
            oldest_open_days: row.oldest_open_days,
        }
    }
}

#[derive(Clone)]
pub struct RemediationDistributions {
    issues: Arc<IssueCatalog>,
    sla: Arc<SlaService>,
    clock: Arc<dyn Clock>,
}

opaque_debug!(RemediationDistributions);

impl RemediationDistributions {
    pub fn new(issues: Arc<IssueCatalog>, sla: Arc<SlaService>, clock: Arc<dyn Clock>) -> RemediationDistributions {
        RemediationDistributions { issues, sla, clock }
    }

    pub async fn distribution(
        &self,
        requested_days: i32,
        allowed: &Visibility,
    ) -> Result<RemediationDistribution, PostureError> {
        let window = requested_days.clamp(7, MAX_WINDOW_DAYS);
        let since = self.clock.now().saturating_sub(Duration::days(i64::from(window)));
        let policy = self.sla.policy().await.map_err(PostureError::unexpected)?;
        let visible = every_issue(allowed.clone());
        let resolved: Vec<Resolved> = self
            .issues
            .resolved_durations_since(&visible, since)
            .await
            .map_err(PostureError::unexpected)?
            .into_iter()
            .map(|row| Resolved {
                severity: Some(Severity::of(row.severity.as_deref())),
                seconds: row.resolution_seconds,
            })
            .collect();

        let now = self.clock.now();
        let thresholds = policy.overdue_thresholds(now);
        let mut open = Vec::new();
        for row in self.issues.open_backlog_by_severity(&visible).await.map_err(PostureError::unexpected)? {
            let severity = Severity::of(row.severity.as_deref());
            // An unrecognised severity has no deadline to be late against.
            let (false, Some(oldest)) = (severity == Severity::Unknown, row.oldest_first_seen) else { continue };
            open.push(Open {
                severity: Some(severity),
                total: row.total,
                overdue: self.count_overdue(severity, &thresholds, allowed).await?,
                // `Duration.toDays()`: whole days, the seconds floored then divided.
                oldest_days: Some(arithmetic::seconds_between(oldest, now) / 86_400),
            });
        }
        Ok(RemediationDistribution::calculate(window, &policy, &resolved, &open))
    }

    async fn count_overdue(
        &self,
        severity: Severity,
        thresholds: &BTreeMap<String, time::OffsetDateTime>,
        allowed: &Visibility,
    ) -> Result<i64, PostureError> {
        // No window for this severity: nothing can be late against a deadline nobody set.
        let Some(threshold) = thresholds.get(severity.wire_name()) else { return Ok(0) };
        let filters =
            SlaService::overdue(BTreeMap::from([(severity.wire_name().to_owned(), *threshold)]), allowed.clone());
        self.issues.count(&filters).await.map_err(PostureError::unexpected)
    }
}
