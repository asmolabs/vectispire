//! `EpssRiskMatrix`: CVSS × EPSS, with KEV on top, and nothing else — the score out of a hundred, the tier, and the
//! action a screen translates. The arithmetic is Java's, in Java's order, so a score rounds where Java's rounds.

use serde::Serialize;
use vectispire_domain::java_math;

/// `RecommendedAction`: a token the screen translates, never a sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RecommendedAction {
    #[serde(rename = "P0_KEV_24H")]
    P0Kev24h,
    #[serde(rename = "P0_48H")]
    P048h,
    #[serde(rename = "P1_7D")]
    P17d,
    #[serde(rename = "P2_30D")]
    P230d,
    #[serde(rename = "P3_ROUTINE")]
    P3Routine,
}

impl RecommendedAction {
    pub fn name(self) -> &'static str {
        match self {
            RecommendedAction::P0Kev24h => "P0_KEV_24H",
            RecommendedAction::P048h => "P0_48H",
            RecommendedAction::P17d => "P1_7D",
            RecommendedAction::P230d => "P2_30D",
            RecommendedAction::P3Routine => "P3_ROUTINE",
        }
    }
}

pub const CRITICAL_ARMED: &str = "CRITICAL_ARMED";
pub const HIGH_PROBABLE: &str = "HIGH_PROBABLE";
pub const MEDIUM_THEORETICAL: &str = "MEDIUM_THEORETICAL";
pub const LOW_PROBABILITY: &str = "LOW_PROBABILITY";

/// `calculatePriorityScore`: an unknown CVSS reads 5.0 and an unknown EPSS 0.01; CVSS up to 30 points, EPSS up to 40
/// (reached at 0.50), KEV 30; clamped to [0, 100] and rounded as `Math.round`.
pub fn priority_score(cvss: Option<f64>, epss: Option<f64>, kev: bool) -> i32 {
    let cvss = cvss.unwrap_or(5.0);
    let epss = epss.unwrap_or(0.01);
    let cvss_component = (cvss / 10.0) * 30.0;
    let epss_component = f64::min(40.0, epss * 40.0 * 2.0);
    let kev_component = if kev { 30.0 } else { 0.0 };
    let base = cvss_component + epss_component + kev_component;
    let rounded = java_math::round(base.clamp(0.0, 100.0));
    i32::try_from(rounded).unwrap_or(i32::MAX)
}

/// `determineTier`.
pub fn tier(cvss: Option<f64>, epss: Option<f64>, kev: bool) -> &'static str {
    let cvss = cvss.unwrap_or(5.0);
    let epss = epss.unwrap_or(0.01);
    if kev || (epss >= 0.50 && cvss >= 7.0) {
        CRITICAL_ARMED
    } else if epss >= 0.20 || (epss >= 0.05 && cvss >= 7.0) {
        HIGH_PROBABLE
    } else if cvss >= 7.0 && epss < 0.05 {
        MEDIUM_THEORETICAL
    } else {
        LOW_PROBABILITY
    }
}

/// `determineAction`: a tier this version does not name is routine.
pub fn action(tier: &str, kev: bool) -> RecommendedAction {
    match tier {
        CRITICAL_ARMED if kev => RecommendedAction::P0Kev24h,
        CRITICAL_ARMED => RecommendedAction::P048h,
        HIGH_PROBABLE => RecommendedAction::P17d,
        MEDIUM_THEORETICAL => RecommendedAction::P230d,
        _ => RecommendedAction::P3Routine,
    }
}
