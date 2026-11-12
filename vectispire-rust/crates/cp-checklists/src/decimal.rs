//! A decimal as `BigDecimal` holds it, and a ratio a rule states (`Ratios`).
//!
//! **Decimal, never a double.** The ratio enters the item's content digest through the rule's canonical form, so
//! `0.6` must be written the same way every time; and 3 of 5 lines against 0.6 must say "met", which binary floating
//! point does not promise. A ratio keeps four decimals at most, which keeps its written form plain.

use std::cmp::Ordering;

use crate::{Refused, refused};

/// An exact decimal: an unscaled magnitude and a scale, as `new BigDecimal(text)` reads `0.60` (60, scale 2) or
/// `6E-1` (6, scale 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decimal {
    negative: bool,
    /// The unscaled magnitude's decimal digits, without leading zeros; `"0"` for zero.
    digits: String,
    scale: i64,
}

impl Decimal {
    /// A JSON number's text — `-`, digits, a fraction, an exponent — or `None` for anything else.
    pub fn parse(text: &str) -> Option<Decimal> {
        let (negative, rest) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text.strip_prefix('+').unwrap_or(text)),
        };
        let (mantissa, exponent) = match rest.find(['e', 'E']) {
            Some(at) => (rest.get(..at)?, rest.get(at.saturating_add(1)..)?.parse::<i64>().ok()?),
            None => (rest, 0),
        };
        let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        if whole.is_empty() && fraction.is_empty()
            || !whole.bytes().chain(fraction.bytes()).all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let joined = format!("{whole}{fraction}");
        let digits = joined.trim_start_matches('0');
        let scale = i64::try_from(fraction.len()).ok()?.checked_sub(exponent)?;
        Some(Decimal {
            negative: negative && !digits.is_empty(),
            digits: if digits.is_empty() { "0".to_owned() } else { digits.to_owned() },
            scale,
        })
    }

    /// An integer's value.
    pub fn of_integer(text: &str) -> Option<Decimal> {
        Decimal::parse(text).filter(|decimal| decimal.scale == 0)
    }

    fn is_zero(&self) -> bool {
        self.digits == "0"
    }

    pub fn signum(&self) -> i32 {
        if self.is_zero() {
            0
        } else if self.negative {
            -1
        } else {
            1
        }
    }

    /// `compareTo(BigDecimal.ONE)` for a value that is not negative.
    fn cmp_one(&self) -> Ordering {
        // 1 at this scale is 10^scale: compare the digit counts, then the digits, once both are at one scale.
        if self.is_zero() {
            return Ordering::Less;
        }
        if self.scale < 0 {
            // At least ten.
            return Ordering::Greater;
        }
        if self.scale == 0 {
            return if self.digits == "1" { Ordering::Equal } else { Ordering::Greater };
        }
        let Ok(scale) = usize::try_from(self.scale) else { return Ordering::Less };
        let one_length = scale.saturating_add(1);
        self.digits.len().cmp(&one_length).then_with(|| self.digits.as_str().cmp(&format!("1{}", "0".repeat(scale))))
    }

    /// `stripTrailingZeros`: zero is `0`, scale 0, as the JDK writes it since 8.
    pub fn strip_trailing_zeros(&self) -> Decimal {
        if self.is_zero() {
            return Decimal { negative: false, digits: "0".to_owned(), scale: 0 };
        }
        let trimmed = self.digits.trim_end_matches('0');
        let dropped = i64::try_from(self.digits.len().saturating_sub(trimmed.len())).unwrap_or(0);
        Decimal { negative: self.negative, digits: trimmed.to_owned(), scale: self.scale.saturating_sub(dropped) }
    }

    /// `toPlainString`: no exponent, the scale's zeros kept.
    pub fn to_plain_string(&self) -> String {
        let sign = if self.negative { "-" } else { "" };
        if self.scale <= 0 {
            let zeros = usize::try_from(self.scale.unsigned_abs()).unwrap_or(0);
            return if self.is_zero() { "0".to_owned() } else { format!("{sign}{}{}", self.digits, "0".repeat(zeros)) };
        }
        let scale = usize::try_from(self.scale).unwrap_or(0);
        let padded = format!("{:0>width$}", self.digits, width = scale.saturating_add(1));
        let point = padded.len().saturating_sub(scale);
        format!("{sign}{}.{}", padded.get(..point).unwrap_or("0"), padded.get(point..).unwrap_or(""))
    }
}

/// A ratio in its one written form: in [0, 1], at most four decimals, trailing zeros stripped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ratio {
    /// At most 10,000.
    unscaled: u32,
    /// 0 to 4.
    scale: u32,
}

/// Four decimals are enough for a KPI and keep the written form out of scientific notation.
pub const SCALE: i64 = 4;

impl Ratio {
    /// `Ratios.require`: refused outside [0, 1] — or at 0 where `zero_allowed` is false, since "at least nothing
    /// covered" is no coverage rule — or past four decimals.
    pub fn require(ratio: &Decimal, what: &str, zero_allowed: bool) -> Result<Ratio, Refused> {
        if ratio.signum() < 0 || ratio.cmp_one() == Ordering::Greater || !zero_allowed && ratio.signum() == 0 {
            return Err(refused(format!(
                "{what} is a ratio {} to 1 — 0.6 for 60 %; {} is not.",
                if zero_allowed { "from 0" } else { "above 0" },
                ratio.to_plain_string()
            )));
        }
        let normalized = ratio.strip_trailing_zeros();
        if normalized.scale > SCALE {
            return Err(refused(format!("{what} has at most {SCALE} decimals; {} has more.", ratio.to_plain_string())));
        }
        // Within [0, 1] the stripped scale is 0 to 4: a negative one would be ten or more.
        let scale = u32::try_from(normalized.scale).unwrap_or(0);
        let unscaled = normalized.digits.parse().unwrap_or(0);
        Ok(Ratio { unscaled, scale })
    }

    pub const ONE: Ratio = Ratio { unscaled: 1, scale: 0 };

    pub fn is_one(self) -> bool {
        self == Ratio::ONE
    }

    /// As `BigDecimal.toString` writes it — plain, at this scale.
    pub fn written(self) -> String {
        Decimal { negative: false, digits: self.unscaled.to_string(), scale: i64::from(self.scale) }.to_plain_string()
    }

    /// `ratio.movePointRight(2).stripTrailingZeros().toPlainString() + " %"`.
    pub fn percent(self) -> String {
        let moved = Decimal {
            negative: false,
            digits: self.unscaled.to_string(),
            scale: i64::from(self.scale).saturating_sub(2),
        };
        format!("{} %", moved.strip_trailing_zeros().to_plain_string())
    }

    /// `Ratios.atLeast`: whether `part` of `whole` is at least the ratio, exactly — part × 10^scale ≥ unscaled ×
    /// whole, in a width neither product can overflow.
    pub fn at_least(self, part: i64, whole: i64) -> bool {
        let power = 10_i128.checked_pow(self.scale).unwrap_or(i128::MAX);
        i128::from(part).saturating_mul(power) >= i128::from(self.unscaled).saturating_mul(i128::from(whole))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decimal(text: &str) -> Decimal {
        Decimal::parse(text).unwrap()
    }

    #[test]
    fn a_decimal_is_read_and_written_as_big_decimal_does() {
        assert_eq!(decimal("0.60").to_plain_string(), "0.60");
        assert_eq!(decimal("6E-1").to_plain_string(), "0.6");
        assert_eq!(decimal("1e-5").to_plain_string(), "0.00001");
        assert_eq!(decimal("1.5e2").to_plain_string(), "150");
        assert_eq!(decimal("-0.1").to_plain_string(), "-0.1");
        assert_eq!(decimal("0.0000").strip_trailing_zeros().to_plain_string(), "0");
        assert_eq!(Decimal::parse("."), None);
        assert_eq!(Decimal::parse("1x"), None);
    }

    #[test]
    fn a_ratio_is_bounded_and_written_one_way() {
        assert_eq!(Ratio::require(&decimal("0.60"), "r", true).unwrap().written(), "0.6");
        assert_eq!(Ratio::require(&decimal("1.0"), "r", false).unwrap().written(), "1");
        assert_eq!(Ratio::require(&decimal("0.00010"), "r", true).unwrap().written(), "0.0001");
        assert!(Ratio::require(&decimal("1.0001"), "r", true).is_err());
        assert!(Ratio::require(&decimal("0"), "r", false).is_err());
        assert!(Ratio::require(&decimal("0.00001"), "r", true).is_err());
        assert_eq!(Ratio::require(&decimal("0.125"), "r", true).unwrap().percent(), "12.5 %");
        assert_eq!(Ratio::require(&decimal("1"), "r", true).unwrap().percent(), "100 %");
    }

    #[test]
    fn a_threshold_met_exactly_is_met() {
        let ratio = Ratio::require(&decimal("0.6"), "r", true).unwrap();
        assert!(ratio.at_least(3, 5));
        assert!(!ratio.at_least(2, 5));
        assert!(ratio.at_least(0, 0), "nothing left to resolve meets the ratio");
    }
}
