//! `PostureDigestService`: the weekly posture report, sent at most once a week to the channels the notifications
//! module offers ([`DigestChannels`]). A report needs no queue: it is derived from the database, so a failed send is
//! recomputed next turn — and the audit entry its sending writes is what says it went out.

use std::sync::Arc;

use time::Duration;
use vectispire_cp_audit::{AuditLog, AuditLogQuery, AuditOperation, Record};
use vectispire_cp_db::Visibility;
use vectispire_cp_gate::GateService;
use vectispire_cp_issues::{IssueCatalog, SlaService};
use vectispire_cp_settings::{Setting, Settings};
use vectispire_cp_targets::Clock;

use crate::dashboard::{backlog_by_severity, every_issue};
use crate::digest::{DigestCounts, PostureDigest};
use crate::error::PostureError;
use crate::ports::DigestChannels;
use crate::trends::{BacklogTrend, Lifespan, day_of, iso};

const WEEK_DAYS: i64 = 7;

#[derive(Clone)]
pub struct PostureDigests {
    settings: Arc<Settings>,
    gate: Arc<GateService>,
    sla: Arc<SlaService>,
    issues: Arc<IssueCatalog>,
    audit_log: Arc<AuditLogQuery>,
    audit: Arc<AuditLog>,
    channels: Arc<dyn DigestChannels>,
    clock: Arc<dyn Clock>,
}

opaque_debug!(PostureDigests);

impl PostureDigests {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        settings: Arc<Settings>,
        gate: Arc<GateService>,
        sla: Arc<SlaService>,
        issues: Arc<IssueCatalog>,
        audit_log: Arc<AuditLogQuery>,
        audit: Arc<AuditLog>,
        channels: Arc<dyn DigestChannels>,
        clock: Arc<dyn Clock>,
    ) -> PostureDigests {
        PostureDigests { settings, gate, sla, issues, audit_log, audit, channels, clock }
    }

    /// One turn: whether a report went out. A failure is logged and retried next turn — **no audit entry**, which
    /// would suppress every retry for the rest of the week.
    pub async fn run_once(&self) -> bool {
        match self.send().await {
            Ok(sent) => sent,
            Err(failed) => {
                tracing::warn!("The weekly posture report could not be sent; it will be retried next tick: {failed}");
                false
            }
        }
    }

    async fn send(&self) -> Result<bool, PostureError> {
        if !self.settings.is_enabled(Setting::DigestEnabled).await.map_err(PostureError::unexpected)? {
            return Ok(false);
        }
        let now = self.clock.now();
        let today = day_of(now);
        let week_starting =
            today.checked_sub(Duration::days(i64::from(today.weekday().number_days_from_monday()))).unwrap_or(today);
        let since = week_starting.midnight().assume_utc();
        if self
            .audit_log
            .count_since(AuditOperation::PostureDigestSent.wire_name(), since)
            .await
            .map_err(PostureError::unexpected)?
            > 0
        {
            return Ok(false);
        }
        let destinations = self.channels.destinations().await.map_err(PostureError::Unexpected)?;
        // Nowhere to send is not a failure to retry hourly for a week: the settings screen is where it shows.
        if !destinations.webhook && !destinations.mail {
            return Ok(false);
        }
        let digest = PostureDigest::of(week_starting, &self.counts(now).await?);
        if destinations.webhook {
            self.channels.post_webhook(&digest, now).await.map_err(PostureError::Unexpected)?;
        }
        if destinations.mail {
            self.channels
                .send_mail(&digest.as_subject(), &digest.as_plain_text())
                .await
                .map_err(PostureError::Unexpected)?;
        }
        // Written after the send: recording first would mean a failed POST is never retried. The cost is the reverse —
        // a crash between the two sends one report twice next tick, a duplicate rather than a week of silence.
        let channels = match (destinations.webhook, destinations.mail) {
            (true, true) => " to the webhook and by e-mail",
            (true, false) => " to the webhook",
            _ => " by e-mail",
        };
        // No actor: nobody asked for this one, and inventing a "system" user would put a person who does not exist
        // into a compliance report.
        let description =
            format!("Weekly posture report sent{channels}: {} open, {} late.", digest.open_total, digest.overdue_count);
        self.audit.record(Record::of(AuditOperation::PostureDigestSent, &iso(week_starting), &description, None)).await;
        tracing::info!("Weekly posture report sent for the week of {}.", iso(week_starting));
        Ok(true)
    }

    async fn counts(&self, now: time::OffsetDateTime) -> Result<DigestCounts, PostureError> {
        let everything = Visibility::Everything;
        let posture = self.gate.overview(&everything).await.map_err(PostureError::unexpected)?;
        let to = day_of(now);
        let lifespans: Vec<Lifespan> = self
            .issues
            .observations(&every_issue(everything.clone()))
            .await
            .map_err(PostureError::unexpected)?
            .into_iter()
            .map(|row| Lifespan { first_seen: Some(row.first_seen_at), resolved_at: row.resolved_at })
            .collect();
        let week = BacklogTrend::over(
            &lifespans,
            to.checked_sub(Duration::days(WEEK_DAYS.saturating_sub(1))).unwrap_or(to),
            to,
        );
        Ok(DigestCounts {
            open_total: week.points.last().map_or(0, |point| point.open),
            backlog_by_severity: backlog_by_severity(&self.issues, &everything).await?,
            opened_this_week: week.points.iter().map(|point| point.opened).sum(),
            resolved_this_week: week.points.iter().map(|point| point.resolved).sum(),
            overdue_count: self.sla.count_overdue(&everything).await.map_err(PostureError::unexpected)?,
            failing_targets: posture.failing_count,
            total_targets: posture.total_count,
            never_scanned: posture.never_scanned_count,
            last_scan_failed: posture.last_scan_failed_count,
            mean_days_to_resolve: week.mean_days_to_resolve,
        })
    }
}
