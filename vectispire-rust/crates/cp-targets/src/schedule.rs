//! A target's schedule as an operator sets it — `ScheduleChoice` — and the field rules the repository and image forms
//! share: the cron refusal, the required agent label, `trim`.

use std::collections::{BTreeMap, BTreeSet};

use time::OffsetDateTime;
use vectispire_domain::cron::crontab;
use vectispire_domain::instant::Instant;
use vectispire_domain::schedules::{self, Schedulable};
use vectispire_domain::{ScanTarget, agent_labels, bounded_text, java};

use crate::Targets;
use crate::error::TargetError;
use crate::persistence::{self, StoreError};

/// The width of `url`, `branch`, `name` and `required_agent_label`, and of the image columns: past it the database
/// refused the row at the write, as a 500.
pub const COLUMN_LENGTH: usize = 255;

/// Manual only, an interval, a cron expression — or none of them, which is the installation's default — as the row
/// holds them.
///
/// **Manual only and a schedule exclude each other, and the row never holds both.** Choosing manual only clears the
/// interval and the expression; naming an interval or an expression without saying anything of manual only leaves
/// it, since that is what asking for a schedule means; naming both in one request is refused. The routes'
/// conventions: `None` leaves a field alone, an empty expression clears it, an interval of zero clears the interval
/// — stored as `None`, the one spelling of "not set".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScheduleChoice {
    pub manual_only: bool,
    pub interval_minutes: Option<i32>,
    pub cron: Option<String>,
}

impl ScheduleChoice {
    /// What a new target starts from.
    pub const NONE: ScheduleChoice = ScheduleChoice { manual_only: false, interval_minutes: None, cron: None };

    /// `apply`: the request's choice applied to this one.
    pub fn apply(
        &self,
        manual_only: Option<bool>,
        interval_minutes: Option<i32>,
        cron: Option<&str>,
    ) -> Result<ScheduleChoice, TargetError> {
        if interval_minutes.is_some_and(|minutes| minutes < 0) {
            return Err(TargetError::invalid(
                "The rescan interval is a number of minutes, zero or more; zero clears it.",
            ));
        }
        let expression = match cron {
            Some(cron) => validated_cron(cron)?,
            None => None,
        };
        let names_schedule = interval_minutes.is_some_and(|minutes| minutes > 0) || expression.is_some();
        if manual_only == Some(true) && names_schedule {
            return Err(TargetError::invalid(
                "A target set to manual only takes no interval and no cron expression: choose one or the other.",
            ));
        }
        let manual = manual_only.unwrap_or(!names_schedule && self.manual_only);
        if manual {
            return Ok(ScheduleChoice { manual_only: true, interval_minutes: None, cron: None });
        }
        Ok(ScheduleChoice {
            manual_only: false,
            interval_minutes: match interval_minutes {
                None => self.interval_minutes,
                Some(0) => None,
                Some(minutes) => Some(minutes),
            },
            cron: if cron.is_none() { self.cron.clone() } else { expression },
        })
    }
}

/// `validatedCron`: a usable expression trimmed, `None` for a blank one, or the 400 an operator can read, with the
/// five-field form every screen teaches.
pub fn validated_cron(expression: &str) -> Result<Option<String>, TargetError> {
    let trimmed = java::trim(expression);
    if trimmed.is_empty() {
        return Ok(None);
    }
    if !crontab::is_valid(Some(trimmed)) {
        return Err(TargetError::invalid(format!(
            "Unusable cron expression: \"{trimmed}\". Expected five fields, for example \"0 2 * * *\" (every day at \
             02:00) or \"0 */6 * * *\" (every six hours)."
        )));
    }
    Ok(Some(trimmed.to_owned()))
}

/// `requiredLabel`: normalized on entry — "Production" here and "production" on the agent would never meet, and the
/// scan would wait for an agent that is present — and bounded after, since that is the value stored.
pub fn required_label(value: Option<&str>) -> Result<Option<String>, TargetError> {
    match agent_labels::normalize_requirement(value) {
        Some(label) => Ok(Some(bounded_text::within(&label, COLUMN_LENGTH, "The required agent label")?.to_owned())),
        None => Ok(None),
    }
}

/// `trim`: `String.trim` of a value that may be absent, absent read as empty.
pub fn trim(value: Option<&str>) -> &str {
    java::trim(value.unwrap_or(""))
}

/// `optional`: trimmed, `None` when nothing is left.
pub fn optional(value: Option<&str>) -> Option<String> {
    let trimmed = trim(value);
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

impl Targets {
    /// `ChecklistMeasurer.scheduled` over `TargetSchedules`: whether each of these repositories' schedule in force runs
    /// it at least once per `max_age` from `now` on — `Schedules.runsAtLeastEvery(TargetSchedules.of(repository),
    /// defaultInterval(), maxAge, now)`, the scheduler's own reading of the four columns and the installation's default,
    /// so that a checklist never holds an opinion of its own about which targets run. Manual only never does; a
    /// repository that does not exist is absent from the answer. A thousand identifiers per statement.
    pub async fn runs_at_least_every(
        &self,
        repository_ids: &[i64],
        max_age: time::Duration,
        now: OffsetDateTime,
    ) -> Result<BTreeMap<i64, bool>, TargetError> {
        // `defaultInterval()` once for the whole answer, as Java reads it before its loop: every repository judged
        // against the same setting even if an administrator changes it meanwhile.
        let default_minutes = self.default_interval_minutes().await?;
        let ids: Vec<i64> = repository_ids.iter().copied().collect::<BTreeSet<i64>>().into_iter().collect();
        let mut tx = persistence::read(&self.db).await?;
        let rows = persistence::repositories_by_ids(&mut tx, &ids).await?;
        tx.commit().await.map_err(StoreError::from)?;
        let now = instant(now);
        let period_seconds = max_age.whole_seconds();
        Ok(rows
            .iter()
            .map(|row| {
                let cron = crontab::parse(row.scan_cron.as_deref());
                let target = Schedulable {
                    target: ScanTarget::Repository(row.id),
                    manual_only: row.scan_manual_only,
                    cron: &cron,
                    interval_minutes: row.scan_interval_minutes,
                    last_scheduled_at: row.last_scheduled_scan_at.map(instant),
                };
                (row.id, schedules::runs_at_least_every(&target, default_minutes, period_seconds, now))
            })
            .collect())
    }
}

/// The same point as the domain counts it: `unix_timestamp` and `nanosecond` are exactly `Instant`'s two fields.
fn instant(at: OffsetDateTime) -> Instant {
    Instant { epoch_second: at.unix_timestamp(), nano: at.nanosecond() }
}
