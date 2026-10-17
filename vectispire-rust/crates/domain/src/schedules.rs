//! `Schedules`' reading of a target's schedule: which rule is in force, and its interval. Only `inForce` is here
//! (task 2.6, for the target listings); the scheduler's `isDue`, the slot offset and `runsAtLeastEvery` are task
//! 2.7's, beside it.

use crate::cron::crontab::Stored;

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
