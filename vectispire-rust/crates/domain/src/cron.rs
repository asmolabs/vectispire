//! Spring's `CronExpression`, ported: the parser a target's schedule is stored for, and its next fire time.
//!
//! **Why a port and not a crate.** A schedule is stored as the text an operator typed and read back by
//! Spring 7.0's parser — six fields, seconds first; day of week 0 to 7, both ends Sunday; names in either
//! case; the Quartz `L`, `W` and `#` forms; the `@` macros. No Rust crate reads those the same way, and a
//! parser that disagrees by one occurrence scans a fleet at the wrong hour, or never — silently, since an
//! unusable expression schedules nothing. So this follows Spring's classes step by step (`CronExpression`,
//! `CronField`, `BitsCronField`, `QuartzCronField`, `CompositeCronField`), quirks included, and is held to
//! `reference/cron/`: 187 expressions, their refusal sentences and their next fire times, written by Spring.
//!
//! Time is UTC, as `CronExpressions` reads it: a fleet across zones must agree on when "0 2 * * *" is.
//! [`CronSchedule::parse`] is Spring's parser; [`crontab`] is the product's reading on top of it — the
//! five-field form with seconds prepended, blank as absent, unusable as never.

use crate::instant::Instant;
use crate::java;

/// Spring's `CronExpression.MAX_ATTEMPTS`: how many rounds a search takes before it gives up — "the 30th
/// of February" finds nothing, after this many tries rather than for ever.
const MAX_ATTEMPTS: u32 = 366;

const MACROS: [(&str, &str); 7] = [
    ("@yearly", "0 0 0 1 1 *"),
    ("@annually", "0 0 0 1 1 *"),
    ("@monthly", "0 0 0 1 * *"),
    ("@weekly", "0 0 0 * * 0"),
    ("@daily", "0 0 0 * * *"),
    ("@midnight", "0 0 0 * * *"),
    ("@hourly", "0 0 * * * *"),
];

const MONTHS: [&str; 12] = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];
const DAYS: [&str; 7] = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"];

/// An expression Spring refuses, with Spring's sentence: the operator reads it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidCron(pub String);

/// A parsed expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronSchedule {
    /// Biggest change first, as Spring orders them, ending on the nanosecond so a match lands on zero.
    fields: Vec<Field>,
}

impl CronSchedule {
    /// `CronExpression.parse`.
    pub fn parse(expression: &str) -> Result<CronSchedule, InvalidCron> {
        if expression.is_empty() {
            return Err(InvalidCron("Expression must not be empty".to_owned()));
        }
        let expression = resolve_macros(expression);
        // `StringUtils.tokenizeToStringArray(expression, " ")`: split on the space only, each token trimmed
        // as `String.trim` trims, empty ones dropped — a tab joins two fields, a lone U+001F vanishes.
        let tokens: Vec<&str> = expression.split(' ').map(java::trim).filter(|token| !token.is_empty()).collect();
        let [seconds, minutes, hours, days_of_month, months, days_of_week] = tokens.as_slice() else {
            return Err(InvalidCron(format!(
                "Cron expression must consist of 6 fields (found {} in \"{expression}\")",
                tokens.len()
            )));
        };
        // Parsed in Java's order, seconds first, so that the first refusal reported is the same one.
        let parsed = (|| {
            let seconds = bits_field(seconds, Kind::Second)?;
            let minutes = bits_field(minutes, Kind::Minute)?;
            let hours = bits_field(hours, Kind::Hour)?;
            let days_of_month = parse_days_of_month(days_of_month)?;
            let months = bits_field(&replace_ordinals(months, &MONTHS), Kind::Month)?;
            let days_of_week = parse_days_of_week(days_of_week)?;
            Ok::<_, String>(vec![
                days_of_week,
                months,
                days_of_month,
                hours,
                minutes,
                seconds,
                Field::Bits { kind: Kind::Nano, bits: 1 },
            ])
        })();
        parsed
            .map(|fields| CronSchedule { fields })
            .map_err(|message| InvalidCron(format!("{message} in cron expression \"{expression}\"")))
    }

    /// `CronExpression.isValidExpression`.
    pub fn is_valid(expression: &str) -> bool {
        CronSchedule::parse(expression).is_ok()
    }

    /// `next(from)` in UTC: the first match strictly after `after`, or `None` when the search gives up —
    /// an expression that cannot fire, or a date past the range Java's `LocalDate` can hold.
    pub fn next(&self, after: Instant) -> Option<Instant> {
        let mut temporal = DateTime::from_instant(after)?.plus_nanos(1)?;
        for _ in 0..MAX_ATTEMPTS {
            let result = self.next_or_same_internal(temporal)?;
            if result == temporal {
                return result.to_instant();
            }
            temporal = result;
        }
        None
    }

    fn next_or_same_internal(&self, mut temporal: DateTime) -> Option<DateTime> {
        for field in &self.fields {
            temporal = field.next_or_same(temporal)?;
        }
        Some(temporal)
    }
}

/// `resolveMacros`: trimmed, then compared to each macro as `equalsIgnoreCase` compares — which also
/// matches the dotted and dotless i to `i` and the Kelvin sign to `k`.
fn resolve_macros(expression: &str) -> String {
    let trimmed = java::trim(expression);
    MACROS
        .iter()
        .find(|(name, _)| equals_ignore_case(trimmed, name))
        .map_or_else(|| trimmed.to_owned(), |(_, value)| (*value).to_owned())
}

/// `String.equalsIgnoreCase` against an ASCII lower-case `expected`: a character matches when it is the
/// letter, its upper case, or one of the three non-ASCII characters whose case mapping lands on it.
fn equals_ignore_case(text: &str, expected: &str) -> bool {
    text.chars().count() == expected.chars().count()
        && text.chars().zip(expected.chars()).all(|(c, e)| {
            c.to_ascii_lowercase() == e
                || matches!((c, e), ('\u{130}' | '\u{131}', 'i') | ('\u{212a}', 'k') | ('\u{17f}', 's'))
        })
}

/// `CronField.replaceOrdinals`: the whole field upper-cased (`toUpperCase(Locale.ROOT)`: `ſ` is `S`, `ß`
/// is `SS`), then each name replaced by its number, in the list's order.
fn replace_ordinals(value: &str, names: &[&str]) -> String {
    let mut value = value.to_uppercase();
    for (index, name) in names.iter().enumerate() {
        value = value.replace(name, &index.saturating_add(1).to_string());
    }
    value
}

fn parse_days_of_month(value: &str) -> Result<Field, String> {
    if !is_quartz_days_of_month(value) {
        return bits_date(value, Kind::DayOfMonth);
    }
    parse_list(value, Kind::DayOfMonth, |part| {
        if is_quartz_days_of_month(part) { quartz_days_of_month(part) } else { bits_date(part, Kind::DayOfMonth) }
    })
}

fn parse_days_of_week(value: &str) -> Result<Field, String> {
    let value = replace_ordinals(value, &DAYS);
    if !is_quartz_days_of_week(&value) {
        return bits_days_of_week(&value);
    }
    parse_list(&value, Kind::DayOfWeek, |part| {
        if is_quartz_days_of_week(part) { quartz_days_of_week(part) } else { bits_days_of_week(part) }
    })
}

/// `CronField.parseList`: split on commas, empty members kept — each then refused as Spring refuses it.
fn parse_list(value: &str, kind: Kind, parse: impl Fn(&str) -> Result<Field, String>) -> Result<Field, String> {
    let mut fields = value.split(',').map(parse).collect::<Result<Vec<_>, _>>()?;
    if fields.len() == 1 {
        return fields.pop().ok_or_else(String::new);
    }
    Ok(Field::Composite { kind, fields })
}

fn is_quartz_days_of_month(value: &str) -> bool {
    value.contains('L') || value.contains('W')
}

fn is_quartz_days_of_week(value: &str) -> bool {
    value.contains('L') || value.contains('#')
}

/// `BitsCronField.parseDaysOfWeek`: 0 is Sunday, stored as 7 as `java.time` numbers it.
fn bits_days_of_week(value: &str) -> Result<Field, String> {
    let field = bits_date(value, Kind::DayOfWeek)?;
    Ok(match field {
        Field::Bits { kind, bits } if bits & 1 != 0 => Field::Bits { kind, bits: (bits | 1 << 7) & !1 },
        other => other,
    })
}

/// `BitsCronField.parseDate`: `?` is `*`.
fn bits_date(value: &str, kind: Kind) -> Result<Field, String> {
    bits_field(if value == "?" { "*" } else { value }, kind)
}

/// `BitsCronField.parseField`: comma-separated ranges and steps into a bit set; a refusal carries the field
/// in quotes after Spring's sentence.
fn bits_field(value: &str, kind: Kind) -> Result<Field, String> {
    if value.is_empty() {
        return Err("Value must not be empty".to_owned());
    }
    let mut bits = 0u64;
    let parsed = value.split(',').try_for_each(|part| {
        let Some((range_text, delta_text)) = part.split_once('/') else {
            let (min, max) = parse_range(part, kind)?;
            set_range(&mut bits, min, max);
            return Ok(());
        };
        let (mut min, mut max) = parse_range(range_text, kind)?;
        if !range_text.contains('-') {
            (min, max) = value_range(min, kind.range().1)?;
        }
        let delta = java::parse_int(delta_text)?;
        if delta <= 0 {
            return Err("Incrementer delta must be 1 or higher".to_owned());
        }
        if delta == 1 {
            set_range(&mut bits, min, max);
        } else {
            // An `int` loop, wrapping as Java's does: a step of 2147483647 from 1 wraps negative and sets
            // the bits its shifts mask to — 0 and 63 — before it ends.
            let mut i = min;
            while i <= max {
                set_bit(&mut bits, i);
                i = i.wrapping_add(delta);
            }
        }
        Ok(())
    });
    parsed.map_err(|message: String| format!("{message} '{value}'"))?;
    Ok(Field::Bits { kind, bits })
}

/// `BitsCronField.parseRange`.
fn parse_range(value: &str, kind: Kind) -> Result<(i32, i32), String> {
    if value == "*" {
        return Ok(kind.range());
    }
    let Some((low, high)) = value.split_once('-') else {
        let single = kind.check_valid_value(java::parse_int(value)?)?;
        return Ok((single, single));
    };
    let min = java::parse_int_in(low)?;
    let max = java::parse_int_in(high)?;
    let mut min = kind.check_valid_value(min)?;
    let max = kind.check_valid_value(max)?;
    // As the minimum of a range, Sunday is 0, not 7.
    if kind == Kind::DayOfWeek && min == 7 {
        min = 0;
    }
    value_range(min, max)
}

/// `ValueRange.of(min, max)`.
fn value_range(min: i32, max: i32) -> Result<(i32, i32), String> {
    if min > max { Err("Minimum value must be less than maximum value".to_owned()) } else { Ok((min, max)) }
}

/// `1L << index`, the shift masked to six bits as Java masks it.
fn set_bit(bits: &mut u64, index: i32) {
    *bits |= 1u64.wrapping_shl(index.cast_unsigned());
}

/// `BitsCronField.setBits(range)`: `MASK << min & MASK >>> -(max + 1)`, Java's shifts.
fn set_range(bits: &mut u64, min: i32, max: i32) {
    if min == max {
        set_bit(bits, min);
    } else {
        let low = u64::MAX.wrapping_shl(min.cast_unsigned());
        let high = u64::MAX.wrapping_shr(max.wrapping_add(1).wrapping_neg().cast_unsigned());
        *bits |= low & high;
    }
}

/// `QuartzCronField.parseDaysOfMonth`: `L`, `L-n`, `LW`, `nW`.
fn quartz_days_of_month(value: &str) -> Result<Field, String> {
    if let Some(index) = value.rfind('L') {
        if index != 0 {
            return Err(format!("Unrecognized characters before 'L' in '{value}'"));
        }
        let adjuster = if value == "LW" {
            Adjuster::LastWeekdayOfMonth
        } else if value == "L" {
            Adjuster::LastDayOfMonth
        } else {
            let offset = java::parse_int_in(value.get(1..).unwrap_or_default())?;
            if offset >= 0 {
                return Err(format!("Offset '{offset} should be < 0 '{value}'"));
            }
            Adjuster::LastDayWithOffset(offset)
        };
        return Ok(Field::Quartz { kind: Kind::DayOfMonth, roll: Kind::DayOfMonth, adjuster });
    }
    if let Some(index) = value.rfind('W') {
        if index == 0 {
            return Err(format!("No day-of-month before 'W' in '{value}'"));
        }
        if !value.ends_with('W') {
            return Err(format!("Unrecognized characters after 'W' in '{value}'"));
        }
        let day = Kind::DayOfMonth.check_valid_value(java::parse_int_in(value.get(..index).unwrap_or_default())?)?;
        return Ok(Field::Quartz {
            kind: Kind::DayOfMonth,
            roll: Kind::DayOfMonth,
            adjuster: Adjuster::WeekdayNearestTo(day),
        });
    }
    Err(format!("No 'L' or 'W' found in '{value}'"))
}

/// `QuartzCronField.parseDaysOfWeek`: `dL`, `d#n`. They roll forward by the month, not the week.
fn quartz_days_of_week(value: &str) -> Result<Field, String> {
    if let Some(index) = value.rfind('L') {
        if !value.ends_with('L') {
            return Err(format!("Unrecognized characters after 'L' in '{value}'"));
        }
        if index == 0 {
            return Err(format!("No day-of-week before 'L' in '{value}'"));
        }
        let day = parse_day_of_week(value.get(..index).unwrap_or_default())?;
        return Ok(Field::Quartz {
            kind: Kind::DayOfWeek,
            roll: Kind::DayOfMonth,
            adjuster: Adjuster::LastInMonth(day),
        });
    }
    if let Some(index) = value.rfind('#') {
        if index == 0 {
            return Err(format!("No day-of-week before '#' in '{value}'"));
        }
        if value.ends_with('#') {
            return Err(format!("No ordinal after '#' in '{value}'"));
        }
        let day = parse_day_of_week(value.get(..index).unwrap_or_default())?;
        let ordinal = java::parse_int_in(value.get(index.saturating_add(1)..).unwrap_or_default())?;
        if ordinal <= 0 {
            return Err(format!("Ordinal '{ordinal}' in '{value}' must be positive number "));
        }
        return Ok(Field::Quartz {
            kind: Kind::DayOfWeek,
            roll: Kind::DayOfMonth,
            adjuster: Adjuster::DayOfWeekInMonth(ordinal, day),
        });
    }
    Err(format!("No 'L' or '#' found in '{value}'"))
}

/// `QuartzCronField.parseDayOfWeek`: 0 is Sunday; `DayOfWeek.of`'s refusal otherwise.
fn parse_day_of_week(value: &str) -> Result<i32, String> {
    let day = java::parse_int(value)?;
    let day = if day == 0 { 7 } else { day };
    if (1..=7).contains(&day) { Ok(day) } else { Err(format!("Invalid value for DayOfWeek: {day} '{value}'")) }
}

/// One of the six fields, or the trailing nanosecond.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Field {
    Bits { kind: Kind, bits: u64 },
    Quartz { kind: Kind, roll: Kind, adjuster: Adjuster },
    Composite { kind: Kind, fields: Vec<Field> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Adjuster {
    LastDayOfMonth,
    LastWeekdayOfMonth,
    LastDayWithOffset(i32),
    WeekdayNearestTo(i32),
    LastInMonth(i32),
    DayOfWeekInMonth(i32, i32),
}

impl Field {
    fn next_or_same(&self, temporal: DateTime) -> Option<DateTime> {
        match self {
            Field::Bits { kind, bits } => bits_next_or_same(*kind, *bits, temporal),
            Field::Quartz { kind, roll, adjuster } => {
                let result = adjuster.adjust(temporal)?;
                if result >= temporal {
                    return Some(result);
                }
                // Before the start: roll forward and try once more.
                let rolled = roll.roll_forward(temporal)?;
                Some(kind.reset(adjuster.adjust(rolled)?))
            }
            // The earliest of the members that found one.
            Field::Composite { fields, .. } => fields.iter().filter_map(|field| field.next_or_same(temporal)).min(),
        }
    }
}

/// `BitsCronField.nextSetBit`: the lowest set bit at or above `from`, Java's shift masking `from` to six
/// bits — the nanosecond field asks with values up to 999,999,999.
fn next_set_bit(bits: u64, from: i64) -> Option<i64> {
    let masked = bits & u64::MAX.wrapping_shl(u32::try_from(from.rem_euclid(64)).unwrap_or(0));
    (masked != 0).then(|| i64::from(masked.trailing_zeros()))
}

/// `BitsCronField.nextOrSame`.
fn bits_next_or_same(kind: Kind, bits: u64, mut temporal: DateTime) -> Option<DateTime> {
    let current = kind.get(temporal);
    let next = match next_set_bit(bits, current) {
        Some(next) => next,
        None => {
            temporal = kind.roll_forward(temporal)?;
            match next_set_bit(bits, kind.get(temporal)) {
                Some(next) => next,
                None => {
                    temporal = kind.roll_forward(temporal)?;
                    next_set_bit(bits, 0)?
                }
            }
        }
    };
    if next == current {
        return Some(temporal);
    }
    let mut next = next;
    let mut count = 0u32;
    let mut current = kind.get(temporal);
    while current != next && count < MAX_ATTEMPTS {
        count = count.saturating_add(1);
        temporal = kind.elapse_until(temporal, next)?;
        current = kind.get(temporal);
        match next_set_bit(bits, current) {
            Some(found) => next = found,
            None => {
                temporal = kind.roll_forward(temporal)?;
                next = match next_set_bit(bits, kind.get(temporal)) {
                    Some(found) => found,
                    None => {
                        temporal = kind.roll_forward(temporal)?;
                        next_set_bit(bits, 0)?
                    }
                };
                current = kind.get(temporal);
            }
        }
    }
    // Spring gives up once the count reaches the limit, even on the round that found the value.
    if count >= MAX_ATTEMPTS {
        return None;
    }
    Some(kind.reset(temporal))
}

impl Adjuster {
    fn adjust(self, temporal: DateTime) -> Option<DateTime> {
        match self {
            Adjuster::LastDayOfMonth => Some(rollback_to_midnight(temporal, temporal.last_day_of_month())),
            Adjuster::LastWeekdayOfMonth => {
                let last = temporal.last_day_of_month();
                let result = match last.day_of_week() {
                    6 => last.plus_days(-1)?,
                    7 => last.plus_days(-2)?,
                    _ => last,
                };
                Some(rollback_to_midnight(temporal, result))
            }
            Adjuster::LastDayWithOffset(offset) => {
                Some(rollback_to_midnight(temporal, temporal.last_day_of_month().plus_days(i64::from(offset))?))
            }
            Adjuster::WeekdayNearestTo(day) => weekday_nearest_to(temporal, i64::from(day)),
            Adjuster::LastInMonth(day) => {
                let last = temporal.last_day_of_month();
                let difference = i64::from(day).checked_sub(last.day_of_week())?;
                let difference = if difference > 0 { difference.checked_sub(7)? } else { difference };
                Some(rollback_to_midnight(temporal, last.plus_days(difference)?))
            }
            Adjuster::DayOfWeekInMonth(ordinal, day) => {
                // `TemporalAdjusters.dayOfWeekInMonth` can overflow into another month; Spring then tries the
                // same adjustment from there, twelve times at most.
                let mut temporal = temporal;
                for _ in 0..12 {
                    let first = temporal.with_day(1)?;
                    let shift =
                        i32::try_from((i64::from(day).checked_sub(first.day_of_week())?.checked_add(7)?).rem_euclid(7))
                            .ok()?;
                    // `(int) ((ordinal - 1L) * 7L)`, then an `int` sum: both wrap in Java, so a large ordinal
                    // lands where Java's wrapped count of days lands — backwards, for 613566757.
                    let shift = shift.wrapping_add(ordinal.wrapping_sub(1).wrapping_mul(7));
                    let result = first.plus_days(i64::from(shift))?;
                    if result.month == temporal.month {
                        return Some(rollback_to_midnight(temporal, result));
                    }
                    temporal = result;
                }
                None
            }
        }
    }
}

/// `QuartzCronField.weekdayNearestTo`: a Saturday moves to the Friday before, a Sunday to the Monday after
/// — and a Saturday the 1st to Monday the 3rd, staying in the month.
fn weekday_nearest_to(temporal: DateTime, day: i64) -> Option<DateTime> {
    let current = i64::from(temporal.day);
    let weekday = temporal.day_of_week();
    if (current == day && weekday <= 5)
        || (weekday == 5 && Some(current) == day.checked_sub(1))
        || (weekday == 1 && Some(current) == day.checked_add(1))
        || (weekday == 1 && day == 1 && current == 3)
    {
        return Some(temporal);
    }
    let mut temporal = temporal;
    let mut current = current;
    for _ in 0..MAX_ATTEMPTS {
        if current == day {
            let moved = match temporal.day_of_week() {
                6 if day != 1 => temporal.plus_days(-1)?,
                6 => temporal.plus_days(2)?,
                7 => temporal.plus_days(1)?,
                _ => temporal,
            };
            return Some(moved.at_midnight());
        }
        temporal = Kind::DayOfMonth.elapse_until(temporal, day)?;
        current = i64::from(temporal.day);
    }
    None
}

/// `QuartzCronField.rollbackToMidnight`: the start itself when the adjustment stayed on its day, so the
/// result is never before where the search began; midnight of the new day otherwise.
fn rollback_to_midnight(current: DateTime, result: DateTime) -> DateTime {
    if result.day == current.day { current } else { result.at_midnight() }
}

/// `CronField.Type`: one `ChronoField` and the unit above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Nano,
    Second,
    Minute,
    Hour,
    DayOfMonth,
    Month,
    DayOfWeek,
}

impl Kind {
    /// The field's general range, `ChronoField.range()` — 1 to 31 for the day of the month.
    fn range(self) -> (i32, i32) {
        match self {
            Kind::Nano => (0, 999_999_999),
            Kind::Second | Kind::Minute => (0, 59),
            Kind::Hour => (0, 23),
            Kind::DayOfMonth => (1, 31),
            Kind::Month => (1, 12),
            Kind::DayOfWeek => (1, 7),
        }
    }

    /// `ChronoField.toString()`, in the refusal sentence.
    fn name(self) -> &'static str {
        match self {
            Kind::Nano => "NanoOfSecond",
            Kind::Second => "SecondOfMinute",
            Kind::Minute => "MinuteOfHour",
            Kind::Hour => "HourOfDay",
            Kind::DayOfMonth => "DayOfMonth",
            Kind::Month => "MonthOfYear",
            Kind::DayOfWeek => "DayOfWeek",
        }
    }

    /// `Type.checkValidValue`: in range, or `ValueRange`'s sentence; 0 is accepted as a day of the week.
    fn check_valid_value(self, value: i32) -> Result<i32, String> {
        let (min, max) = self.range();
        if (self == Kind::DayOfWeek && value == 0) || (min..=max).contains(&value) {
            return Ok(value);
        }
        let range = if self == Kind::DayOfMonth { "1 - 28/31".to_owned() } else { format!("{min} - {max}") };
        Err(format!("Invalid value for {} (valid values {range}): {value}", self.name()))
    }

    fn get(self, t: DateTime) -> i64 {
        match self {
            Kind::Nano => i64::from(t.nano),
            Kind::Second => i64::from(t.second),
            Kind::Minute => i64::from(t.minute),
            Kind::Hour => i64::from(t.hour),
            Kind::DayOfMonth => i64::from(t.day),
            Kind::Month => i64::from(t.month),
            Kind::DayOfWeek => t.day_of_week(),
        }
    }

    /// `temporal.range(field)`: the actual range at this date — the month's length for its day.
    fn actual_range(self, t: DateTime) -> (i64, i64) {
        match self {
            Kind::DayOfMonth => (1, i64::from(month_length(t.year, t.month))),
            other => {
                let (min, max) = other.range();
                (i64::from(min), i64::from(max))
            }
        }
    }

    /// `temporal.with(field, value)`, for values already known valid.
    fn with(self, t: DateTime, value: i64) -> Option<DateTime> {
        let small = |v: i64| u8::try_from(v).ok();
        match self {
            Kind::Nano => Some(DateTime { nano: u32::try_from(value).ok()?, ..t }),
            Kind::Second => Some(DateTime { second: small(value)?, ..t }),
            Kind::Minute => Some(DateTime { minute: small(value)?, ..t }),
            Kind::Hour => Some(DateTime { hour: small(value)?, ..t }),
            Kind::DayOfMonth => t.with_day(small(value)?),
            Kind::Month => {
                let month = small(value)?;
                Some(DateTime { month, day: t.day.min(month_length(t.year, month)), ..t })
            }
            Kind::DayOfWeek => t.plus_days(value.checked_sub(t.day_of_week())?),
        }
    }

    /// `field.getBaseUnit().addTo(temporal, amount)`.
    fn add_base(self, t: DateTime, amount: i64) -> Option<DateTime> {
        match self {
            Kind::Nano => t.plus_nanos(amount),
            Kind::Second => t.plus_seconds(amount),
            Kind::Minute => t.plus_seconds(amount.checked_mul(60)?),
            Kind::Hour => t.plus_seconds(amount.checked_mul(3_600)?),
            Kind::DayOfMonth | Kind::DayOfWeek => t.plus_days(amount),
            Kind::Month => t.plus_months(amount),
        }
    }

    /// `higherOrder.addTo(temporal, 1)`.
    fn add_higher(self, t: DateTime) -> Option<DateTime> {
        match self {
            Kind::Nano => t.plus_seconds(1),
            Kind::Second => t.plus_seconds(60),
            Kind::Minute => t.plus_seconds(3_600),
            Kind::Hour => t.plus_days(1),
            Kind::DayOfMonth => t.plus_months(1),
            Kind::Month => t.plus_months(12),
            Kind::DayOfWeek => t.plus_days(7),
        }
    }

    /// `Type.rollForward`: up one unit of the field above, this field at its minimum — for the day of the
    /// week, Monday of that week, which may be earlier than where it landed.
    fn roll_forward(self, t: DateTime) -> Option<DateTime> {
        let result = self.add_higher(t)?;
        self.with(result, self.actual_range(result).0)
    }

    /// `Type.elapseUntil`.
    fn elapse_until(self, t: DateTime, goal: i64) -> Option<DateTime> {
        let current = self.get(t);
        let (min, max) = self.actual_range(t);
        if current < goal {
            if (min..=max).contains(&goal) {
                self.with(t, goal)
            } else {
                // The goal does not exist here (the 30th of February): roll past the end.
                self.add_base(t, max.checked_sub(current)?.checked_add(1)?)
            }
        } else {
            self.add_base(t, goal.checked_add(max)?.checked_sub(current)?.checked_add(1)?.checked_sub(min)?)
        }
    }

    /// `Type.reset`: this field's lower fields to their minimum — the day of the month to 1 under the month.
    fn reset(self, t: DateTime) -> DateTime {
        match self {
            Kind::Nano => t,
            Kind::Second => DateTime { nano: 0, ..t },
            Kind::Minute => DateTime { second: 0, nano: 0, ..t },
            Kind::Hour => DateTime { minute: 0, second: 0, nano: 0, ..t },
            Kind::DayOfMonth | Kind::DayOfWeek => t.at_midnight(),
            Kind::Month => DateTime { day: 1, ..t.at_midnight() },
        }
    }
}

/// A UTC date and time as `ZonedDateTime` in `ZoneOffset.UTC` holds it, ordered as time is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct DateTime {
    year: i64,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    nano: u32,
}

/// `java.time`'s year range: a date beyond it is where Java throws, and where the search stops here.
const MAX_YEAR: i64 = 999_999_999;

fn is_leap(year: i64) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

fn month_length(year: i64, month: u8) -> u8 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to a civil date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: u8, day: u8) -> Option<i64> {
    let year = if month <= 2 { year.checked_sub(1)? } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month = i64::from(month);
    let shifted = if month > 2 { month.checked_sub(3)? } else { month.checked_add(9)? };
    let day_of_year =
        shifted.checked_mul(153)?.checked_add(2)?.checked_div(5)?.checked_add(i64::from(day))?.checked_sub(1)?;
    let day_of_era = year_of_era
        .checked_mul(365)?
        .checked_add(year_of_era.checked_div(4)?)?
        .checked_sub(year_of_era.checked_div(100)?)?
        .checked_add(day_of_year)?;
    era.checked_mul(146_097)?.checked_add(day_of_era)?.checked_sub(719_468)
}

/// The civil date of a day count from 1970-01-01 (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> Option<(i64, u8, u8)> {
    let z = days.checked_add(719_468)?;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era = day_of_era
        .checked_sub(day_of_era.checked_div(1_460)?)?
        .checked_add(day_of_era.checked_div(36_524)?)?
        .checked_sub(day_of_era.checked_div(146_096)?)?
        .checked_div(365)?;
    let day_of_year = day_of_era.checked_sub(
        year_of_era
            .checked_mul(365)?
            .checked_add(year_of_era.checked_div(4)?)?
            .checked_sub(year_of_era.checked_div(100)?)?,
    )?;
    let shifted = day_of_year.checked_mul(5)?.checked_add(2)?.checked_div(153)?;
    let day = day_of_year.checked_sub(shifted.checked_mul(153)?.checked_add(2)?.checked_div(5)?)?.checked_add(1)?;
    let month = if shifted < 10 { shifted.checked_add(3)? } else { shifted.checked_sub(9)? };
    let year = year_of_era.checked_add(era.checked_mul(400)?)?;
    let year = if month <= 2 { year.checked_add(1)? } else { year };
    Some((year, u8::try_from(month).ok()?, u8::try_from(day).ok()?))
}

impl DateTime {
    fn from_instant(instant: Instant) -> Option<DateTime> {
        let days = instant.epoch_second.div_euclid(Instant::SECONDS_PER_DAY);
        let of_day = instant.epoch_second.rem_euclid(Instant::SECONDS_PER_DAY);
        let (year, month, day) = civil_from_days(days)?;
        Some(DateTime {
            year,
            month,
            day,
            hour: u8::try_from(of_day.checked_div(3_600)?).ok()?,
            minute: u8::try_from(of_day.rem_euclid(3_600).checked_div(60)?).ok()?,
            second: u8::try_from(of_day.rem_euclid(60)).ok()?,
            nano: instant.nano,
        })
    }

    fn to_instant(self) -> Option<Instant> {
        let days = days_from_civil(self.year, self.month, self.day)?;
        let of_day = i64::from(self.hour)
            .checked_mul(3_600)?
            .checked_add(i64::from(self.minute).checked_mul(60)?)?
            .checked_add(i64::from(self.second))?;
        Some(Instant {
            epoch_second: days.checked_mul(Instant::SECONDS_PER_DAY)?.checked_add(of_day)?,
            nano: self.nano,
        })
    }

    /// ISO day of the week, Monday 1 to Sunday 7; 1970-01-01 was a Thursday.
    fn day_of_week(self) -> i64 {
        days_from_civil(self.year, self.month, self.day)
            .map_or(1, |days| days.checked_add(3).map_or(1, |d| d.rem_euclid(7)).saturating_add(1))
    }

    fn with_day(self, day: u8) -> Option<DateTime> {
        (1..=month_length(self.year, self.month)).contains(&day).then_some(DateTime { day, ..self })
    }

    fn last_day_of_month(self) -> DateTime {
        DateTime { day: month_length(self.year, self.month), ..self }
    }

    fn at_midnight(self) -> DateTime {
        DateTime { hour: 0, minute: 0, second: 0, nano: 0, ..self }
    }

    fn checked_year(self) -> Option<DateTime> {
        (-MAX_YEAR..=MAX_YEAR).contains(&self.year).then_some(self)
    }

    fn plus_days(self, days: i64) -> Option<DateTime> {
        let (year, month, day) = civil_from_days(days_from_civil(self.year, self.month, self.day)?.checked_add(days)?)?;
        DateTime { year, month, day, ..self }.checked_year()
    }

    /// `plusMonths`: the day clamped to the new month's length, as `java.time` clamps it.
    fn plus_months(self, months: i64) -> Option<DateTime> {
        let total =
            self.year.checked_mul(12)?.checked_add(i64::from(self.month).checked_sub(1)?)?.checked_add(months)?;
        let year = total.div_euclid(12);
        let month = u8::try_from(total.rem_euclid(12).checked_add(1)?).ok()?;
        DateTime { year, month, day: self.day.min(month_length(year, month)), ..self }.checked_year()
    }

    fn plus_seconds(self, seconds: i64) -> Option<DateTime> {
        let instant = self.to_instant()?;
        DateTime::from_instant(Instant { epoch_second: instant.epoch_second.checked_add(seconds)?, ..instant })?
            .checked_year()
    }

    fn plus_nanos(self, nanos: i64) -> Option<DateTime> {
        let total = i64::from(self.nano).checked_add(nanos)?;
        let carried = self.plus_seconds(total.div_euclid(1_000_000_000))?;
        Some(DateTime { nano: u32::try_from(total.rem_euclid(1_000_000_000)).ok()?, ..carried })
    }
}

/// The product's reading of a stored expression — `CronExpressions` in `vectispire-core`.
pub mod crontab {
    use super::{CronSchedule, Instant};
    use crate::java;

    /// What a target's stored expression schedules.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Stored {
        /// No expression: the target runs on its interval.
        Absent,
        /// An expression Spring refuses: the target is **never** scheduled — not quietly moved onto a
        /// drifting interval the operator did not ask for.
        Never,
        Parsed(CronSchedule),
    }

    impl Stored {
        /// The next occurrence after `from`; `None` for absent, never, or an expression that will not fire.
        pub fn next_after(&self, from: Instant) -> Option<Instant> {
            match self {
                Stored::Parsed(schedule) => schedule.next(from),
                Stored::Absent | Stored::Never => None,
            }
        }
    }

    /// `CronExpressions.parse`: blank (`String.isBlank`) is absent, unusable is never.
    pub fn parse(expression: Option<&str>) -> Stored {
        match expression.filter(|e| !java::is_blank(e)) {
            None => Stored::Absent,
            Some(expression) => CronSchedule::parse(&normalize(expression)).map_or(Stored::Never, Stored::Parsed),
        }
    }

    /// `CronExpressions.isValid`, for the screen that validates one.
    pub fn is_valid(expression: Option<&str>) -> bool {
        expression.is_some_and(|e| !java::is_blank(e) && CronSchedule::is_valid(&normalize(e)))
    }

    /// `CronExpressions.normalize`: five fields — what `crontab` means, and what every screen and message
    /// teaches — become Spring's six with **`0`** seconds prepended (`*` would fire sixty times through the
    /// minute); anything else is left as written, so an expression stored in six fields keeps running.
    /// Fields are counted on runs of Java's `\s` — space, tab, the line breaks, U+000B and U+000C — after
    /// `String.trim`.
    pub fn normalize(expression: &str) -> String {
        let trimmed = java::trim(expression);
        let fields = trimmed.split([' ', '\t', '\n', '\u{b}', '\u{c}', '\r']).filter(|f| !f.is_empty());
        if fields.count() == 5 { format!("0 {trimmed}") } else { trimmed.to_owned() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(year: i64, month: u8, day: u8) -> DateTime {
        DateTime { year, month, day, hour: 1, minute: 2, second: 3, nano: 4 }
    }

    #[test]
    fn a_month_shorter_than_the_day_clamps_it_as_java_time_does() {
        // `plusMonths` and `with(MONTH_OF_YEAR, …)` keep the day only where the month has it. The search's
        // resets hide a wrong day from the reference set, so the arithmetic is held here.
        assert_eq!(date(2024, 1, 31).plus_months(1), Some(date(2024, 2, 29)));
        assert_eq!(date(2023, 1, 31).plus_months(1), Some(date(2023, 2, 28)));
        assert_eq!(date(2024, 2, 29).plus_months(12), Some(date(2025, 2, 28)));
        assert_eq!(Kind::Month.with(date(2026, 3, 31), 4), Some(date(2026, 4, 30)));
    }
}
