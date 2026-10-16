//! How Spring reads a value into a duration, a size or a boolean — so that `PT5M`, `5m`, `16KB` and
//! `yes` mean to the Rust control plane what they meant to the Java one, on the same environment.
//!
//! **Conversions as Boot's binder applies them**, not as one would write them: a duration with no
//! unit is **milliseconds**, a size with none is **bytes**, units of a size are case-sensitive
//! (`16KB`, not `16kb`), and a boolean is `true`/`on`/`yes`/`1` or `false`/`off`/`no`/`0` in any case.

use std::time::Duration;

/// `DurationStyle.detectAndParse`: ISO-8601 (`PT5M`, `P1D`, `PT0.5S`) or the simple form (`5m`, `60m`,
/// `15s`, `1h`, `2d`, `100ms`, `10us`, `1ns`, or a bare number of milliseconds).
pub fn parse_duration(text: &str) -> Result<Duration, String> {
    let invalid = || format!("'{text}' is not a valid duration");
    let value = text.trim();
    if value.starts_with(['p', 'P']) || value.starts_with(['+', '-']) && value[1..].starts_with(['p', 'P']) {
        return parse_iso(value).ok_or_else(invalid);
    }
    let split = value.find(|c: char| !(c.is_ascii_digit() || c == '+' || c == '-')).unwrap_or(value.len());
    let (digits, unit) = value.split_at(split);
    if digits.is_empty() || unit.len() > 2 || !unit.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(invalid());
    }
    let amount: i128 = digits.parse().map_err(|_| invalid())?;
    let nanos_per: i128 = match unit.to_lowercase().as_str() {
        "" | "ms" => 1_000_000,
        "ns" => 1,
        "us" => 1_000,
        "s" => 1_000_000_000,
        "m" => 60 * 1_000_000_000,
        "h" => 3_600 * 1_000_000_000,
        "d" => 86_400 * 1_000_000_000,
        _ => return Err(invalid()),
    };
    let nanos = amount.checked_mul(nanos_per).ok_or_else(invalid)?;
    // A negative duration is not one a setting means; the Java side would hold it and misbehave.
    u64::try_from(nanos).map(Duration::from_nanos).map_err(|_| format!("'{text}' is a negative duration"))
}

/// `java.time.Duration.parse`: `PnDTnHnMn.nS`, days as 24 hours, no years or months.
fn parse_iso(text: &str) -> Option<Duration> {
    let upper = text.to_uppercase();
    let rest = upper.strip_prefix('+').unwrap_or(&upper);
    if rest.starts_with('-') {
        return None;
    }
    let rest = rest.strip_prefix('P')?;
    let (date, time) = match rest.split_once('T') {
        Some((date, time)) => (date, Some(time)),
        None => (rest, None),
    };
    let mut total = 0f64;
    let mut seen = false;
    let mut number = String::new();
    for c in date.chars() {
        match c {
            'D' => {
                total += number.parse::<f64>().ok()? * 86_400.0;
                number.clear();
                seen = true;
            }
            c if c.is_ascii_digit() => number.push(c),
            _ => return None,
        }
    }
    if !number.is_empty() {
        return None;
    }
    if let Some(time) = time {
        if time.is_empty() {
            return None;
        }
        for c in time.chars() {
            let factor = match c {
                'H' => 3_600.0,
                'M' => 60.0,
                'S' => 1.0,
                c if c.is_ascii_digit() || c == '.' => {
                    number.push(c);
                    continue;
                }
                _ => return None,
            };
            total += number.parse::<f64>().ok()? * factor;
            number.clear();
            seen = true;
        }
        if !number.is_empty() {
            return None;
        }
    }
    if seen { Duration::try_from_secs_f64(total).ok() } else { None }
}

/// `DataSize.parse`: a number and `B`, `KB`, `MB`, `GB` or `TB` (powers of 1024), bytes without one.
pub fn parse_data_size(text: &str) -> Result<u64, String> {
    let invalid = || format!("'{text}' is not a valid data size");
    let value = text.trim();
    let split = value.find(|c: char| !(c.is_ascii_digit() || c == '+' || c == '-')).unwrap_or(value.len());
    let (digits, unit) = value.split_at(split);
    if digits.is_empty() || unit.len() > 2 || !unit.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(invalid());
    }
    let amount: i128 = digits.parse().map_err(|_| invalid())?;
    let factor: i128 = match unit {
        "" | "B" => 1,
        "KB" => 1 << 10,
        "MB" => 1 << 20,
        "GB" => 1 << 30,
        "TB" => 1 << 40,
        _ => return Err(invalid()),
    };
    u64::try_from(amount.checked_mul(factor).ok_or_else(invalid)?).map_err(|_| invalid())
}

/// `StringToBooleanConverter`: empty is no value; anything outside the two lists is refused.
pub fn parse_bool(text: &str) -> Result<Option<bool>, String> {
    match text.trim().to_lowercase().as_str() {
        "" => Ok(None),
        "true" | "on" | "yes" | "1" => Ok(Some(true)),
        "false" | "off" | "no" | "0" => Ok(Some(false)),
        _ => Err(format!("Invalid boolean value '{}'", text.trim())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_are_read_as_boot_reads_them() {
        let secs = Duration::from_secs;
        assert_eq!(parse_duration("PT5M"), Ok(secs(300)));
        assert_eq!(parse_duration("pt1m30s"), Ok(secs(90)));
        assert_eq!(parse_duration("P1D"), Ok(secs(86_400)));
        assert_eq!(parse_duration("PT0.5S"), Ok(Duration::from_millis(500)));
        assert_eq!(parse_duration("5m"), Ok(secs(300)));
        assert_eq!(parse_duration("60M"), Ok(secs(3_600)));
        assert_eq!(parse_duration("12h"), Ok(secs(43_200)));
        assert_eq!(parse_duration("180s"), Ok(secs(180)));
        assert_eq!(parse_duration("100ms"), Ok(Duration::from_millis(100)));
        assert_eq!(parse_duration("250"), Ok(Duration::from_millis(250)), "no unit is milliseconds");
        for refused in ["", "m", "5 m", "5x", "PT", "P", "PT5", "1.5s", "5mm"] {
            assert!(parse_duration(refused).is_err(), "{refused:?}");
        }
        assert!(parse_duration("-5s").is_err());
    }

    #[test]
    fn sizes_are_read_as_boot_reads_them() {
        assert_eq!(parse_data_size("1MB"), Ok(1 << 20));
        assert_eq!(parse_data_size("16KB"), Ok(16 << 10));
        assert_eq!(parse_data_size("256MB"), Ok(256 << 20));
        assert_eq!(parse_data_size("100"), Ok(100), "no unit is bytes");
        assert_eq!(parse_data_size("10B"), Ok(10));
        assert!(parse_data_size("1mb").is_err(), "the units are case-sensitive");
        assert!(parse_data_size("1MiB").is_err());
        assert!(parse_data_size("").is_err());
    }

    #[test]
    fn booleans_are_read_as_boot_reads_them() {
        for yes in ["true", "TRUE", "on", "Yes", "1", " true "] {
            assert_eq!(parse_bool(yes), Ok(Some(true)), "{yes}");
        }
        for no in ["false", "Off", "no", "0"] {
            assert_eq!(parse_bool(no), Ok(Some(false)), "{no}");
        }
        assert_eq!(parse_bool(""), Ok(None));
        assert!(parse_bool("maybe").is_err());
    }
}
