//! Grades and the formula of decision 0036 — `common.domain.scorecard`: [`SecurityGrade`], [`CandidateScore`] with its
//! [`Weights`] and [`Counts`], the cards ([`SecurityScorecard`], [`PortfolioScorecard`]) and the badge's SVG.
//!
//! **One formula** since 0.11.0: `100 × exp(−risk points / k)`, held at one, an exploited issue capping it at
//! [`EXPLOITED_CAP`]. Every card, the ranking and the public badge read it through [`CandidateScore::of`] with
//! [`Weights::PROPOSED`]; the simulation alone hands it other weights.

use serde::Serialize;
use vectispire_domain::java;

use crate::arithmetic;

/// A letter grade, as the wire spells it — the enum's name (`A_PLUS`, `NO_DATA`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum SecurityGrade {
    #[serde(rename = "A_PLUS")]
    APlus,
    #[serde(rename = "A")]
    A,
    #[serde(rename = "B")]
    B,
    #[serde(rename = "C")]
    C,
    #[serde(rename = "D")]
    D,
    #[serde(rename = "F")]
    F,
    /// Nothing in scope scanned to completion (decision 0007): no grade, not an A+.
    #[serde(rename = "NO_DATA")]
    NoData,
}

impl SecurityGrade {
    /// In declaration order — the order a distribution lists them in (`EnumMap`).
    pub const ALL: [SecurityGrade; 7] = [
        SecurityGrade::APlus,
        SecurityGrade::A,
        SecurityGrade::B,
        SecurityGrade::C,
        SecurityGrade::D,
        SecurityGrade::F,
        SecurityGrade::NoData,
    ];

    /// The enum's name, as the wire and the reference set spell it.
    pub fn name(self) -> &'static str {
        match self {
            SecurityGrade::APlus => "A_PLUS",
            SecurityGrade::A => "A",
            SecurityGrade::B => "B",
            SecurityGrade::C => "C",
            SecurityGrade::D => "D",
            SecurityGrade::F => "F",
            SecurityGrade::NoData => "NO_DATA",
        }
    }

    /// What the badge prints.
    pub fn label(self) -> &'static str {
        match self {
            SecurityGrade::APlus => "A+",
            SecurityGrade::A => "A",
            SecurityGrade::B => "B",
            SecurityGrade::C => "C",
            SecurityGrade::D => "D",
            SecurityGrade::F => "F",
            SecurityGrade::NoData => "no data",
        }
    }

    /// The badge's colour.
    pub fn badge_color(self) -> &'static str {
        match self {
            SecurityGrade::APlus => "#4c1",
            SecurityGrade::A => "#97ca00",
            SecurityGrade::B => "#dfb317",
            SecurityGrade::C => "#fe7d37",
            SecurityGrade::D => "#e05d44",
            SecurityGrade::F => "#d9534f",
            SecurityGrade::NoData => "#9f9f9f",
        }
    }

    /// `fromScore`: never [`SecurityGrade::NoData`] — a score is a grade.
    pub fn from_score(score: i32) -> SecurityGrade {
        match score {
            95.. => SecurityGrade::APlus,
            85.. => SecurityGrade::A,
            70.. => SecurityGrade::B,
            55.. => SecurityGrade::C,
            40.. => SecurityGrade::D,
            _ => SecurityGrade::F,
        }
    }
}

/// The ceiling an exploited issue holds a score at, whatever else is open.
pub const EXPLOITED_CAP: i32 = 54;

const MAX_PARAMETER: f64 = 1_000_000.0;

/// The weights of each class and the `k` that scales them.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Weights {
    pub exploited: f64,
    pub critical: f64,
    pub high: f64,
    pub medium: f64,
    pub low: f64,
    pub licence: f64,
    pub k: f64,
}

impl Weights {
    /// The production weights — a contract (decision 0036), not a setting.
    pub const PROPOSED: Weights =
        Weights { exploited: 25.0, critical: 10.0, high: 4.0, medium: 0.5, low: 0.125, licence: 4.0, k: 55.0 };

    /// `new Weights(..)`: each a finite number in `[0, 1 000 000]`, checked in the record's order, and `k` above zero —
    /// refused with Java's sentence, which the simulation route answers 400 with.
    pub fn new(
        exploited: f64,
        critical: f64,
        high: f64,
        medium: f64,
        low: f64,
        licence: f64,
        k: f64,
    ) -> Result<Weights, String> {
        for (name, value) in [
            ("exploited", exploited),
            ("critical", critical),
            ("high", high),
            ("medium", medium),
            ("low", low),
            ("licence", licence),
            ("k", k),
        ] {
            if !value.is_finite() || value < 0.0 || value > MAX_PARAMETER {
                return Err(format!("{name} must be a number between 0 and 1000000."));
            }
        }
        if k <= 0.0 {
            return Err("k must be greater than zero.".to_owned());
        }
        Ok(Weights { exploited, critical, high, medium, low, licence, k })
    }
}

/// The open backlog in the classes the formula weighs: an exploited issue in its own class and in no severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    pub exploited: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub licences: i64,
}

impl Counts {
    pub const NONE: Counts = Counts { exploited: 0, critical: 0, high: 0, medium: 0, low: 0, licences: 0 };
}

/// A score, its grade and the risk points behind it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoreResult {
    pub score: i32,
    pub grade: SecurityGrade,
    pub risk_points: f64,
}

/// `CandidateScore`: the formula.
#[derive(Debug, Clone, Copy)]
pub struct CandidateScore;

impl CandidateScore {
    /// The weighted backlog, in Java's order of addition — a sum of doubles is not associative.
    pub fn risk_points(counts: &Counts, weights: &Weights) -> f64 {
        counts.exploited as f64 * weights.exploited
            + counts.critical as f64 * weights.critical
            + counts.high as f64 * weights.high
            + counts.medium as f64 * weights.medium
            + counts.low as f64 * weights.low
            + counts.licences as f64 * weights.licence
    }

    /// The unrounded, uncapped score.
    pub fn exact(counts: &Counts, weights: &Weights) -> f64 {
        100.0 * arithmetic::strict_exp(-Self::risk_points(counts, weights) / weights.k)
    }

    /// The score — rounded, at least one, capped by an exploited issue — and its grade.
    pub fn of(counts: &Counts, weights: &Weights) -> ScoreResult {
        let rounded = arithmetic::round(Self::exact(counts, weights)).max(1);
        // `(int) Math.max(1, Math.round(..))`: at most 100, so the narrowing loses nothing.
        let mut score = i32::try_from(rounded).unwrap_or(i32::MAX);
        if counts.exploited > 0 {
            score = score.min(EXPLOITED_CAP);
        }
        ScoreResult { score, grade: SecurityGrade::from_score(score), risk_points: Self::risk_points(counts, weights) }
    }
}

/// `SecurityScorecard.WeakestTarget`: the target a scope's grade, or the portfolio's weakest, is read from.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WeakestTarget {
    pub target_kind: String,
    pub target_id: i64,
    pub target_name: String,
    pub score: i32,
    pub grade: SecurityGrade,
    pub risk_points: f64,
}

/// A target's, a project's or a solution's card.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityScorecard {
    pub target_id: Option<i64>,
    pub target_kind: Option<String>,
    pub target_name: Option<String>,
    pub score: Option<i32>,
    pub grade: SecurityGrade,
    pub risk_points: Option<f64>,
    pub total_targets: i32,
    pub observed_targets: i32,
    pub open_critical_count: i64,
    pub open_high_count: i64,
    pub open_kev_count: i64,
    pub overdue_count: i64,
    pub license_violation_count: i64,
    pub has_attestation: bool,
    pub weakest_target: Option<WeakestTarget>,
    pub recommendations: Vec<String>,
}

/// How many targets read one grade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GradeCount {
    pub grade: SecurityGrade,
    pub targets: i64,
}

/// The estate the caller sees: no grade of its own (decision 0036).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortfolioScorecard {
    pub total_targets: i32,
    pub observed_targets: i32,
    pub grades: Vec<GradeCount>,
    pub weakest_target: Option<WeakestTarget>,
    pub risk_points: f64,
    pub open_critical_count: i64,
    pub open_high_count: i64,
    pub open_kev_count: i64,
    pub overdue_count: i64,
    pub license_violation_count: i64,
}

/// `SvgBadgeGenerator.generateBadge`: the shield, byte for byte — widths counted in UTF-16 units as `length()`.
pub fn badge(subject: &str, status: &str, color: &str) -> String {
    let label = subject;
    let grade = status;
    // Java's `int` arithmetic over two short labels; saturating, which no label a badge carries comes near.
    let label_width = java::utf16_len(label).saturating_mul(6).saturating_add(20);
    let status_width = java::utf16_len(grade).saturating_mul(7).saturating_add(18);
    let total_width = label_width.saturating_add(status_width);
    let label_text_x = label_width.saturating_mul(10) / 2;
    let status_text_x = label_width.saturating_mul(10).saturating_add(status_width.saturating_mul(10) / 2);
    let label_length = label_width.saturating_sub(10).saturating_mul(10);
    let status_length = status_width.saturating_sub(10).saturating_mul(10);
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{label}: {grade}">
  <title>{label}: {grade}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#555"/>
    <rect x="{label_width}" width="{status_width}" height="20" fill="{color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="{label_text_x}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{label_length}">{label}</text>
    <text x="{label_text_x}" y="140" transform="scale(.1)" fill="#fff" textLength="{label_length}">{label}</text>
    <text aria-hidden="true" x="{status_text_x}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{status_length}">{grade}</text>
    <text x="{status_text_x}" y="140" transform="scale(.1)" fill="#fff" font-weight="bold" textLength="{status_length}">{grade}</text>
  </g>
</svg>"##
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_backlog_reads_a_hundred_and_an_exploited_one_is_capped() {
        assert_eq!(CandidateScore::of(&Counts::NONE, &Weights::PROPOSED).score, 100);
        let exploited = Counts { exploited: 1, ..Counts::NONE };
        assert_eq!(CandidateScore::of(&exploited, &Weights::PROPOSED).score, EXPLOITED_CAP);
        let huge = Counts { critical: 1_000, ..Counts::NONE };
        assert_eq!(CandidateScore::of(&huge, &Weights::PROPOSED).score, 1);
    }
}
