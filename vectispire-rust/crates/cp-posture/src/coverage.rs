//! How much of a scope the graded backlog was read from — `SecurityScorecardService.Coverage` and `cappedToCoverage`.
//!
//! **Observed means holding a completed scan**, the scan that produced the backlog: not the compliance summary's "the
//! latest scan succeeded" (a scan in flight must not flip a published badge to "no data"), and not the freshness window,
//! which is a deployment setting a public grade must not depend on.

use crate::arithmetic;

/// A scope's targets, and how many hold a completed scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Coverage {
    pub total: i32,
    pub observed: i32,
}

impl Coverage {
    /// One target, observed or not.
    pub fn of_one(observed: bool) -> Coverage {
        Coverage { total: 1, observed: i32::from(observed) }
    }

    /// The targets never scanned.
    pub fn never(self) -> i32 {
        self.total.saturating_sub(self.observed)
    }
}

/// A score held at the observed share of its scope, in the compliance summary's rounding — `Math.round(float)` of a
/// `float` division, which a `double` would round differently at some shares.
pub fn capped(score: i32, total: i32, observed: i32) -> i32 {
    let coverage = Coverage { total, observed };
    if coverage.never() > 0 {
        #[allow(clippy::cast_precision_loss)]
        let share = (observed as f32 / total as f32) * 100.0;
        score.min(arithmetic::round_f32(share))
    } else {
        score
    }
}
