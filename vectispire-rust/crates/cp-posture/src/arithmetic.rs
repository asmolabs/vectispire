//! The four pieces of Java arithmetic every posture figure goes through, written once: `Math.round` on a double and
//! on a float (`vectispire_domain::java_math`, re-exported), `Duration.between(..).toSeconds()`, and
//! `String.format("%.Nf")`.
//!
//! Each differs from the Rust spelling that reads the same: `f64::round` rounds a half away from zero where Java
//! rounds it towards positive infinity, `time::Duration::whole_seconds` truncates towards zero where Java's floors,
//! and `format!("{:.1}")` rounds a tie to even where Java's `Formatter` rounds it up — 3.25 is "3.2" here and "3.3"
//! there, which the weekly report's reference set caught.

use time::OffsetDateTime;

// `Math.round` on a double and on a float, and the tenth every figure of days is shown with, live in the domain crate
// since compliance's MTTR and its engine round as posture does: one spelling of Java's rounding for both.
pub use vectispire_domain::java_math::{round, round_f32, tenths};

/// `Duration.between(from, to).toSeconds()`: whole seconds, **floored** — a duration of minus half a second is minus
/// one second in Java, where truncation would say zero.
pub fn seconds_between(from: OffsetDateTime, to: OffsetDateTime) -> i64 {
    let nanos = to.unix_timestamp_nanos().saturating_sub(from.unix_timestamp_nanos());
    i64::try_from(nanos.div_euclid(1_000_000_000)).unwrap_or(if nanos < 0 { i64::MIN } else { i64::MAX })
}

/// `String.format(Locale.ROOT, "%.<digits>f", value)`. `Formatter` rounds **the shortest decimal that reads back as the
/// double** — `Double.toString`'s digits — half up, not the double's exact binary value: 12.35 is
/// 12.3499999999999996… and prints "12.4" in Java, where rounding the exact value gives "12.3".
pub fn fixed(value: f64, digits: usize) -> String {
    if !value.is_finite() {
        return if value.is_nan() {
            "NaN".to_owned()
        } else if value > 0.0 {
            "Infinity".to_owned()
        } else {
            "-Infinity".to_owned()
        };
    }
    // Rust's `Display` writes the shortest round-trip digits too, and never in exponent form.
    let shortest = format!("{}", value.abs());
    let (whole, fraction) = shortest.split_once('.').unwrap_or((shortest.as_str(), ""));
    let mut kept: Vec<u8> = whole.bytes().map(|b| b.saturating_sub(b'0')).collect();
    let mut decimals: Vec<u8> = fraction.bytes().take(digits).map(|b| b.saturating_sub(b'0')).collect();
    decimals.resize(digits, 0);
    kept.extend(decimals);
    if fraction.as_bytes().get(digits).is_some_and(|b| *b >= b'5') {
        let mut index = kept.len();
        loop {
            if index == 0 {
                kept.insert(0, 1);
                break;
            }
            index = index.saturating_sub(1);
            if let Some(digit) = kept.get_mut(index) {
                if *digit == 9 {
                    *digit = 0;
                } else {
                    *digit = digit.saturating_add(1);
                    break;
                }
            }
        }
    }
    let text: String = kept.iter().map(|digit| char::from(b'0'.saturating_add(*digit))).collect();
    let (integer, decimals) = text.split_at(text.len().saturating_sub(digits));
    // `Formatter` signs by `Double.compare(value, 0.0)`: minus zero, and a negative value rounding to zero, are "-0.0".
    let sign = if value.is_sign_negative() { "-" } else { "" };
    if digits == 0 { format!("{sign}{integer}") } else { format!("{sign}{integer}.{decimals}") }
}

/// `StrictMath.exp` — fdlibm's `__ieee754_exp`, as the JDK carries it (`FdLibm.Exp`), constant for constant.
///
/// **Not `f64::exp`**, which is the platform's libm: macOS's answers an ulp away from fdlibm for about one argument in
/// ten of the score grid, and a published grade must not depend on the machine computing it. The Java side computes
/// the formula with `StrictMath.exp` for the same reason, so both sides are fdlibm everywhere.
pub fn strict_exp(x: f64) -> f64 {
    const HUGE: f64 = 1.0e300;
    let twom1000 = f64::from_bits(0x0170_0000_0000_0000);
    let o_threshold = f64::from_bits(0x4086_2E42_FEFA_39EF);
    let u_threshold = f64::from_bits(0xC087_4910_D52D_3051);
    let (ln2_hi_positive, ln2_hi_negative) =
        (f64::from_bits(0x3FE6_2E42_FEE0_0000), f64::from_bits(0xBFE6_2E42_FEE0_0000));
    let (ln2_lo_positive, ln2_lo_negative) =
        (f64::from_bits(0x3DEA_39EF_3579_3C76), f64::from_bits(0xBDEA_39EF_3579_3C76));
    let invln2 = f64::from_bits(0x3FF7_1547_652B_82FE);
    let p1 = f64::from_bits(0x3FC5_5555_5555_553E);
    let p2 = f64::from_bits(0xBF66_C16C_16BE_BD93);
    let p3 = f64::from_bits(0x3F11_566A_AF25_DE2C);
    let p4 = f64::from_bits(0xBEBB_BD41_C5D2_6BF1);
    let p5 = f64::from_bits(0x3E66_3769_72BE_A4D0);

    let bits = x.to_bits();
    let high = u32::try_from(bits >> 32).unwrap_or(u32::MAX);
    let negative = high >> 31 == 1;
    let magnitude = high & 0x7fff_ffff;

    if magnitude >= 0x4086_2E42 {
        if magnitude >= 0x7ff0_0000 {
            if (magnitude & 0xf_ffff) != 0 || (bits & 0xffff_ffff) != 0 {
                return x + x;
            }
            return if negative { 0.0 } else { x };
        }
        if x > o_threshold {
            return HUGE * HUGE;
        }
        if x < u_threshold {
            return twom1000 * twom1000;
        }
    }

    let (mut x, mut hi, mut lo, mut k) = (x, 0.0, 0.0, 0i32);
    if magnitude > 0x3fd6_2e42 {
        if magnitude < 0x3FF0_A2B2 {
            hi = x - if negative { ln2_hi_negative } else { ln2_hi_positive };
            lo = if negative { ln2_lo_negative } else { ln2_lo_positive };
            k = if negative { -1 } else { 1 };
        } else {
            // |x| < 709.79 here, so the product is within ±1025: the cast truncates toward zero as C's `(int)` does.
            #[allow(clippy::cast_possible_truncation)]
            let truncated = (invln2 * x + if negative { -0.5 } else { 0.5 }) as i32;
            k = truncated;
            let t = f64::from(k);
            hi = x - t * ln2_hi_positive;
            lo = t * ln2_lo_positive;
        }
        x = hi - lo;
    } else if magnitude < 0x3e30_0000 {
        // |x| < 2^-28: `huge + x > one` always holds, and raised the inexact flag in C.
        return 1.0 + x;
    }

    let t = x * x;
    let c = x - t * (p1 + t * (p2 + t * (p3 + t * (p4 + t * p5))));
    if k == 0 {
        return 1.0 - ((x * c) / (c - 2.0) - x);
    }
    let y = 1.0 - ((lo - (x * c) / (2.0 - c)) - hi);
    // `__HI(y) += k << 20`: k's bits into the exponent of y's high word, as C adds them (two's complement, wrapping).
    let with_exponent = |y: f64, k: i32| {
        let bits = y.to_bits();
        let shift = u64::from(k.wrapping_shl(20).cast_unsigned()).wrapping_shl(32);
        f64::from_bits(bits.wrapping_add(shift))
    };
    if k >= -1021 { with_exponent(y, k) } else { with_exponent(y, k.wrapping_add(1000)) * twom1000 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_half_rounds_up_as_java_rounds_it() {
        assert_eq!(round(0.5), 1);
        assert_eq!(round(-0.5), 0);
        assert_eq!(round(-1.5), -1);
        assert_eq!(round(2.4999999999999996), 2);
        assert_eq!(round_f32(66.5), 67);
        assert_eq!(round_f32(-0.5), 0);
        assert_eq!(tenths(-0.05), 0.0);
        assert!(tenths(-0.05).is_sign_positive());
    }

    #[test]
    fn seconds_are_floored() {
        let at = OffsetDateTime::UNIX_EPOCH;
        assert_eq!(seconds_between(at, at + time::Duration::milliseconds(1500)), 1);
        assert_eq!(seconds_between(at + time::Duration::milliseconds(500), at), -1);
    }

    #[test]
    fn a_fixed_tie_rounds_up() {
        assert_eq!(fixed(3.25, 1), "3.3");
        assert_eq!(fixed(0.05, 1), "0.1");
        assert_eq!(fixed(12.5, 2), "12.50");
        assert_eq!(fixed(0.125, 2), "0.13");
        assert_eq!(fixed(12.35, 1), "12.4");
        assert_eq!(fixed(9.995, 2), "10.00");
        assert_eq!(fixed(99.96, 1), "100.0");
        assert_eq!(fixed(-0.04, 1), "-0.0");
        assert_eq!(fixed(2.0, 1), "2.0");
    }

    #[test]
    fn exp_is_fdlibm_s() {
        // `StrictMath.exp` of these, from the JDK: the libm of macOS answers the first an ulp away.
        assert_eq!(strict_exp(-28.0 / 55.0), 0.601041732097793);
        assert_eq!(strict_exp(-0.1), 0.9048374180359595);
        assert_eq!(strict_exp(0.0), 1.0);
        assert_eq!(strict_exp(f64::NEG_INFINITY), 0.0);
        assert_eq!(strict_exp(-800.0), 0.0);
        assert_eq!(strict_exp(1.0), 2.7182818284590455, "fdlibm's, an ulp above `E`");
        assert!(strict_exp(f64::NAN).is_nan());
    }
}
