//! `Schedules`: when a target is due for a rescan, which rule is in force, and how often it runs — the one reading of
//! a target's four schedule columns that the scheduler (task 2.7), the target listings (task 2.6) and a checklist rule
//! share, so that none of them holds an opinion of its own about which targets run.
//!
//! **Held to Java by `reference/scanning/java-answers.json`** (`ScanningReferenceSetTest`): every mode against every
//! kind of last round, the default interval's slots, and the cadence a rule reads. A slot that moved by one second
//! would move a whole estate's weekly round.

use crate::ScanTarget;
use crate::cron::crontab::Stored;
use crate::instant::Instant;

/// `Schedules.Mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Manual,
    Cron,
    Interval,
    Default,
}

impl Mode {
    pub fn wire_name(self) -> &'static str {
        match self {
            Mode::Manual => "manual",
            Mode::Cron => "cron",
            Mode::Interval => "interval",
            Mode::Default => "default",
        }
    }
}

/// `Schedules.InForce`: the mode, and the interval it runs on in minutes — `None` under a cron expression, manual
/// only, and the default when the installation has none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InForce {
    pub mode: Mode,
    pub interval_minutes: Option<i64>,
}

/// `Schedulable.mode`: manual only wins; then **any** stored expression — one Spring refuses included, which
/// schedules nothing rather than falling back to the interval; then a positive interval; then the default.
pub fn mode(manual_only: bool, cron: &Stored, interval_minutes: Option<i32>) -> Mode {
    if manual_only {
        Mode::Manual
    } else if !matches!(cron, Stored::Absent) {
        Mode::Cron
    } else if interval_minutes.is_some_and(|minutes| minutes > 0) {
        Mode::Interval
    } else {
        Mode::Default
    }
}

/// `Schedules.inForce` over `TargetSchedules.of`'s reading of a row: an absent interval is zero, the default is
/// `default_minutes` (`scan_default_interval_days` in minutes), in force only when positive.
pub fn in_force(manual_only: bool, cron: &Stored, interval_minutes: Option<i32>, default_minutes: i64) -> InForce {
    let mode = mode(manual_only, cron, interval_minutes);
    let interval_minutes = match mode {
        Mode::Manual | Mode::Cron => None,
        Mode::Interval => interval_minutes.map(i64::from),
        Mode::Default => (default_minutes > 0).then_some(default_minutes),
    };
    InForce { mode, interval_minutes }
}

/// `Schedules.Schedulable` as `TargetSchedules.of` reads a row: the stored expression as `CronExpressions.parse` reads
/// it, the interval in minutes (absent, zero or negative is "not set"), the last round the scheduler stamped.
#[derive(Debug, Clone, Copy)]
pub struct Schedulable<'a> {
    pub target: ScanTarget,
    pub manual_only: bool,
    pub cron: &'a Stored,
    pub interval_minutes: Option<i32>,
    pub last_scheduled_at: Option<Instant>,
}

impl Schedulable<'_> {
    pub fn mode(&self) -> Mode {
        mode(self.manual_only, self.cron, self.interval_minutes)
    }

    /// `Duration.ofMinutes(interval)` in seconds, zero for an absent one.
    fn interval_seconds(&self) -> i64 {
        i64::from(self.interval_minutes.unwrap_or(0)).saturating_mul(60)
    }
}

const SECONDS_PER_MINUTE: i64 = 60;

/// `Schedules.isDue`: is this target due, by the schedule in force? `default_minutes` is the installation's default
/// interval; zero leaves a target with no schedule of its own unscheduled, as every version before 0.11.0 did.
pub fn is_due(target: &Schedulable<'_>, default_minutes: i64, now: Instant) -> bool {
    match target.mode() {
        Mode::Manual => false,
        Mode::Cron => cron_due(target.cron, target.last_scheduled_at, now),
        Mode::Interval => interval_due(target.interval_seconds(), target.last_scheduled_at, now),
        Mode::Default => default_due(
            target.target,
            default_minutes.saturating_mul(SECONDS_PER_MINUTE),
            target.last_scheduled_at,
            now,
        ),
    }
}

/// `intervalDue`: the interval has elapsed since the last round. A target never scheduled is due at once — switching
/// the scheduler on must not leave it a full interval in silence — and the interval counts from the last round, so it
/// drifts with it, as it always has.
pub fn interval_due(interval_seconds: i64, last: Option<Instant>, now: Instant) -> bool {
    if interval_seconds <= 0 {
        return false;
    }
    match last {
        None => true,
        // Java's `plus` throws past the range of an `Instant`; no stored stamp gets there, and refusing is the side
        // that schedules nothing rather than everything.
        Some(last) => last.plus_seconds(interval_seconds).is_some_and(|due| now >= due),
    }
}

/// `defaultDue`: the target's own moment in the default interval has come round since its last round. The moments are
/// `offset + k × interval` from the epoch — spread over the interval, the same on every tick and every instance, stored
/// nowhere — so a crowd of targets stamped together (the upgrade to 0.11.0 stamped the whole estate) comes apart at its
/// first round instead of running a week's scans in one minute, every week.
pub fn default_due(target: ScanTarget, default_seconds: i64, last: Option<Instant>, now: Instant) -> bool {
    if default_seconds <= 0 {
        return false;
    }
    match last {
        None => true,
        Some(last) => last < latest_slot(target, default_seconds, now),
    }
}

/// `latestSlot`: the last moment at or before `now` at which this target's default round falls, on a whole second.
pub fn latest_slot(target: ScanTarget, interval_seconds: i64, now: Instant) -> Instant {
    let period = interval_seconds.max(1);
    let seconds = now.epoch_second;
    // Java's `long` arithmetic wraps; so does this, for the same answer at the edges nobody reaches.
    Instant::of_epoch_second(
        seconds.wrapping_sub(seconds.wrapping_sub(offset(target, interval_seconds)).rem_euclid(period)),
    )
}

/// `offset`: where in the default interval this target falls, a whole number of seconds in `[0, interval)` — from its
/// kind and identifier alone, never a name or a URL that an edit would move. The kind enters so that repository 7 and
/// image 7 do not share a moment; SplitMix64's finaliser sends consecutive identifiers far apart. **Changing this moves
/// every target once**, which is a single uneven week: reproduce Java's, never improve it.
pub fn offset(target: ScanTarget, interval_seconds: i64) -> i64 {
    let seed = match target {
        ScanTarget::Repository(id) => id.wrapping_mul(2),
        ScanTarget::Container(id) => id.wrapping_mul(2).wrapping_add(1),
    };
    mix(seed).rem_euclid(interval_seconds.max(1))
}

/// SplitMix64's finaliser, in Java's signed `long` with its unsigned shifts.
fn mix(value: i64) -> i64 {
    let mut z = value as u64;
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    (z ^ (z >> 31)) as i64
}

/// `cronDue`: an occurrence has passed since the last round — computed from the last round and not from now, so a
/// round running late catches up the occurrence it missed. A target never scheduled is due at once, but only once the
/// expression is known to fire at all: otherwise the one target whose expression is broken would be the only one to
/// fire unasked.
pub fn cron_due(cron: &Stored, last: Option<Instant>, now: Instant) -> bool {
    if matches!(cron, Stored::Absent) {
        return false;
    }
    match last {
        None => cron.next_after(now).is_some(),
        Some(last) => cron.next_after(last).is_some_and(|next| next <= now),
    }
}

/// `CADENCE_STEPS`: the most occurrences [`runs_at_least_every`] walks before it stops believing a schedule.
pub const CADENCE_STEPS: u32 = 20_000;

/// `runsAtLeastEvery`: whether the schedule in force runs the target at least once in every window of
/// `period_seconds` from `now` on — what a dependency rule asking for a matching schedule reads (decision 0032 §6).
/// Manual only does not run; a cron expression is walked; an interval, or else the default, runs often enough when it
/// is at most the period (the default's rounds fall on fixed slots one interval apart).
pub fn runs_at_least_every(target: &Schedulable<'_>, default_minutes: i64, period_seconds: i64, now: Instant) -> bool {
    let in_force = in_force(target.manual_only, target.cron, target.interval_minutes, default_minutes);
    match in_force.mode {
        Mode::Manual => false,
        Mode::Cron => cron_runs_at_least_every(target.cron, period_seconds, now),
        Mode::Interval | Mode::Default => interval_runs_at_least_every(
            in_force.interval_minutes.unwrap_or(0).saturating_mul(SECONDS_PER_MINUTE),
            period_seconds,
        ),
    }
}

/// The rule once the mode is an interval: at most the period, and a period of none is never met.
pub fn interval_runs_at_least_every(interval_seconds: i64, period_seconds: i64) -> bool {
    period_seconds > 0 && interval_seconds > 0 && interval_seconds <= period_seconds
}

/// The rule for a cron expression: **every gap, not the next one** — "every minute of the first five days of the
/// month" fires often and then waits twenty-five days. The occurrences are walked over two periods, and at least
/// sixty-two days so that a monthly shape shows its longest gap; a walk past [`CADENCE_STEPS`] is not believed, which
/// a rule reads as unmet rather than as a pass nobody checked.
pub fn cron_runs_at_least_every(cron: &Stored, period_seconds: i64, now: Instant) -> bool {
    if period_seconds <= 0 {
        return false;
    }
    const SIXTY_TWO_DAYS: i64 = 62 * 86_400;
    let span = period_seconds.saturating_mul(2);
    let Some(horizon) = now.plus_seconds(span.max(SIXTY_TWO_DAYS)) else { return false };
    let period_nanos = i128::from(period_seconds).saturating_mul(1_000_000_000);
    let mut from = now;
    for _ in 0..CADENCE_STEPS {
        let Some(next) = cron.next_after(from) else { return false };
        if nanos_between(from, next) > period_nanos {
            return false;
        }
        if next > horizon {
            return true;
        }
        from = next;
    }
    false
}

/// `Duration.between(from, to)` in nanoseconds.
fn nanos_between(from: Instant, to: Instant) -> i128 {
    (i128::from(to.epoch_second).saturating_sub(i128::from(from.epoch_second)))
        .saturating_mul(1_000_000_000)
        .saturating_add(i128::from(to.nano))
        .saturating_sub(i128::from(from.nano))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cron::crontab;

    /// `2026-10-18T12:34:56.789Z`, the reference set's instant.
    const NOW: Instant = Instant { epoch_second: 1_792_326_896, nano: 789_000_000 };

    #[test]
    fn each_rule_is_due_at_its_instant_not_a_second_later() {
        // The boundaries the reference set's lasts do not land on: `!now.isBefore(due)`, `isBefore(slot)`, `!isAfter`.
        assert!(interval_due(3_600, NOW.plus_seconds(-3_600), NOW));
        assert!(!interval_due(3_600, NOW.plus_seconds(-3_599), NOW));
        let target = ScanTarget::Repository(42);
        let slot = latest_slot(target, 604_800, NOW);
        assert!(!default_due(target, 604_800, Some(slot), NOW), "stamped at the slot itself: done");
        assert!(default_due(target, 604_800, slot.plus_seconds(-1), NOW));
        let every_minute = crontab::parse(Some("* * * * *"));
        let next = every_minute.next_after(NOW).unwrap();
        assert!(cron_due(&every_minute, Some(NOW), next), "the occurrence's own instant is due");
    }

    #[test]
    fn the_cadence_walks_sixty_two_days_whatever_the_period() {
        // Hourly on the 18th to the 20th of October: daily for two periods from the 18th, then a year's gap — which a
        // walk of two periods alone would never reach.
        let three_days = crontab::parse(Some("0 * 18-20 10 *"));
        assert!(!cron_runs_at_least_every(&three_days, 86_400, NOW));
    }
}
