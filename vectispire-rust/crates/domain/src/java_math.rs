//! `Math.round` as Java rounds, on a double and on a float — the rounding every figure of posture and compliance
//! goes through.
//!
//! `f64::round` rounds a half away from zero where Java rounds it towards positive infinity: `-0.5` is `-1` in Rust
//! and `0` in Java, and a score of 66.5 % must read 67 on both sides. Moved here from `cp-posture`'s `arithmetic`,
//! which re-exports it, so the compliance engine (`compliance::engine`) and the MTTR (`mttr`) round with the same code.

/// `Math.round(double)`: the closest `long`, a half rounded towards positive infinity. Exact: `value - floor(value)` is
/// representable for every double whose floor is, so no addition of 0.5 can round first.
pub fn round(value: f64) -> i64 {
    if value.is_nan() {
        return 0;
    }
    let floor = value.floor();
    let rounded = if value - floor >= 0.5 { floor + 1.0 } else { floor };
    // Java's cast saturates at the ends of `long`, and so does Rust's: the bounds are said, not left to the cast.
    if rounded >= 9.223_372_036_854_776e18 {
        i64::MAX
    } else if rounded < -9.223_372_036_854_776e18 {
        i64::MIN
    } else {
        #[allow(clippy::cast_possible_truncation)] // In range, checked above; integral, being a floor.
        let whole = rounded as i64;
        whole
    }
}

/// `Math.round(float)`: the same on a float, as `SecurityScorecardService.cappedToCoverage` divides in `float`.
pub fn round_f32(value: f32) -> i32 {
    if value.is_nan() {
        return 0;
    }
    let floor = value.floor();
    let rounded = if value - floor >= 0.5 { floor + 1.0 } else { floor };
    if rounded >= 2_147_483_648.0 {
        i32::MAX
    } else if rounded < -2_147_483_648.0 {
        i32::MIN
    } else {
        #[allow(clippy::cast_possible_truncation)] // In range, checked above; integral, being a floor.
        let whole = rounded as i32;
        whole
    }
}

/// `Math.round(value * 10.0) / 10.0`, the one decimal every figure of days and hours is shown with.
pub fn tenths(value: f64) -> f64 {
    round(value * 10.0) as f64 / 10.0
}
