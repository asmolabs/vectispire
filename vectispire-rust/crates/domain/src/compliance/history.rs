//! A framework's monthly verdicts and why each moved — Java's `ComplianceSnapshot` and `ComplianceHistory`.
//!
//! **Stored, not recomputed**: a verdict depends on the backlog of the moment, the freshness window, the targets
//! that existed and the engine's own code, so each capture carries the verdict and the inputs that produced it. And
//! **a line alone would mislead**: the score falls when the estate grows or a detector is switched on, which is
//! progress, so each step carries an attribution — a plausible cause, worded as what changed.

use serde::{Deserialize, Serialize};

use super::framework::{ComplianceFramework, Status};
use super::instant_text;
use crate::instant::Instant;
use crate::java;

/// One framework's verdict and the state of the estate that produced it — `ComplianceSnapshot`. `period` is the
/// month, `yyyy-MM`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceSnapshot {
    pub period: String,
    pub framework: ComplianceFramework,
    pub score: i32,
    pub status: Status,
    pub targets: i32,
    pub observed: i32,
    pub fresh: i32,
    pub freshness_days: i32,
    pub end_of_life_enabled: bool,
    pub code_analysis_reaches: bool,
    pub controls_total: i32,
    pub controls_declared: i32,
    pub soa_findings: i32,
    #[serde(with = "instant_text")]
    pub captured_at: Instant,
}

/// What a score has to be read against: two months with the same shape are comparable — `Shape`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    pub targets: i32,
    pub freshness_days: i32,
    pub end_of_life_enabled: bool,
    pub code_analysis_reaches: bool,
}

impl ComplianceSnapshot {
    pub fn shape(&self) -> Shape {
        Shape {
            targets: self.targets,
            freshness_days: self.freshness_days,
            end_of_life_enabled: self.end_of_life_enabled,
            code_analysis_reaches: self.code_analysis_reaches,
        }
    }
}

/// Below this a score change is noise: one issue opening or closing moves a percentage about this much.
const NOISE: i32 = 2;

/// Why the verdict is where it is, relative to the month before — `Movement`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Movement {
    First,
    EstateGrew,
    EstateShrank,
    RulesChanged,
    Improved,
    Declined,
    Steady,
}

/// One month, attributed — `Step`. `because` is one sentence meant to sit under the point on a chart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Step {
    pub snapshot: ComplianceSnapshot,
    pub delta: i32,
    pub movement: Movement,
    pub because: String,
}

/// One framework's months, oldest first — `Series`. **Read `comparable` before the trend**: a series whose estate
/// kept changing has a shape, not a trend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Series {
    pub framework: ComplianceFramework,
    pub steps: Vec<Step>,
    pub comparable: bool,
}

/// One framework's months, oldest first, each attributed — `ComplianceHistory.of`. Sorted by period as
/// `String.compareTo` sorts, stably: two captures of one month keep the order they came in.
pub fn of(framework: ComplianceFramework, snapshots: &[ComplianceSnapshot]) -> Series {
    let mut ordered: Vec<&ComplianceSnapshot> =
        snapshots.iter().filter(|snapshot| snapshot.framework == framework).collect();
    ordered.sort_by(|left, right| java::compare_utf16(&left.period, &right.period));

    let mut steps = Vec::with_capacity(ordered.len());
    let mut previous: Option<&ComplianceSnapshot> = None;
    for snapshot in ordered {
        steps.push(step(snapshot, previous));
        previous = Some(snapshot);
    }

    let comparable = steps.len() > 1
        && steps.iter().skip(1).all(|step| {
            !matches!(step.movement, Movement::EstateGrew | Movement::EstateShrank | Movement::RulesChanged)
        });
    Series { framework, steps, comparable }
}

/// **The order of the tests is the model**: a change of shape is named first, even when the score also moved,
/// because the shape is what makes two months incomparable.
fn step(snapshot: &ComplianceSnapshot, previous: Option<&ComplianceSnapshot>) -> Step {
    let Some(previous) = previous else {
        return Step {
            snapshot: snapshot.clone(),
            delta: 0,
            movement: Movement::First,
            because: "First capture for this framework: nothing to compare it against yet.".to_owned(),
        };
    };
    let delta = snapshot.score.wrapping_sub(previous.score);
    let (movement, because) = if snapshot.targets > previous.targets {
        (
            Movement::EstateGrew,
            format!(
                "{} target(s) more than last month. A score that falls here is the cost of watching wider, not a \
                 regression.",
                snapshot.targets.wrapping_sub(previous.targets)
            ),
        )
    } else if snapshot.targets < previous.targets {
        (
            Movement::EstateShrank,
            format!(
                "{} target(s) fewer than last month. A score that rises here was bought by removing something.",
                previous.targets.wrapping_sub(snapshot.targets)
            ),
        )
    } else if snapshot.shape() != previous.shape() {
        (Movement::RulesChanged, what_changed(snapshot, previous))
    } else if delta >= NOISE {
        (Movement::Improved, format!("Same estate, same rules, {delta} points up. This one is the work."))
    } else if delta <= NOISE.wrapping_neg() {
        (Movement::Declined, format!("Same estate, same rules, {} points down.", delta.wrapping_neg()))
    } else {
        (Movement::Steady, "Unchanged, within the noise of a single issue.".to_owned())
    };
    Step { snapshot: snapshot.clone(), delta, movement, because }
}

fn what_changed(now: &ComplianceSnapshot, before: &ComplianceSnapshot) -> String {
    if now.freshness_days != before.freshness_days {
        return format!(
            "The freshness window moved from {} to {} days: the same estate is judged against a different rule.",
            before.freshness_days, now.freshness_days
        );
    }
    if now.end_of_life_enabled != before.end_of_life_enabled {
        return if now.end_of_life_enabled {
            "End-of-life detection was switched on: findings appear that were always there."
        } else {
            "End-of-life detection was switched off. Its findings stay open; they are simply no longer refreshed."
        }
        .to_owned();
    }
    if now.code_analysis_reaches {
        "Code analysis now reaches this estate: findings appear that were always there."
    } else {
        "Code analysis no longer reaches this estate — switched off, or no rule covers the languages present."
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(period: &str, score: i32, targets: i32) -> ComplianceSnapshot {
        ComplianceSnapshot {
            period: period.to_owned(),
            framework: ComplianceFramework::Iso27001,
            score,
            status: Status::Partial,
            targets,
            observed: targets,
            fresh: targets,
            freshness_days: 30,
            end_of_life_enabled: true,
            code_analysis_reaches: true,
            controls_total: 4,
            controls_declared: 4,
            soa_findings: 0,
            captured_at: Instant::of_epoch_second(0),
        }
    }

    #[test]
    fn growth_is_not_regression_and_noise_is_not_a_story() {
        // `ComplianceHistoryTest.growthIsNotRegression` and `smallMovesAreNoise`.
        let grew = of(ComplianceFramework::Iso27001, &[snapshot("2026-01", 80, 10), snapshot("2026-02", 60, 13)]);
        assert_eq!(grew.steps.last().map(|step| step.movement), Some(Movement::EstateGrew));
        assert!(!grew.comparable);
        let noise = of(ComplianceFramework::Iso27001, &[snapshot("2026-01", 80, 10), snapshot("2026-02", 79, 10)]);
        assert_eq!(noise.steps.last().map(|step| step.movement), Some(Movement::Steady));
        assert!(noise.comparable);
    }
}
