//! Jackson's coercions, one JSON value at a time: what a record component of each Java type makes of a
//! value of each JSON shape, with the control plane's mapper's defaults (Jackson 2, nothing configured but
//! `FAIL_ON_UNKNOWN_PROPERTIES` off).
//!
//! **Lenient where Jackson is**, and each leniency was measured, not assumed
//! (`reference/artifacts/java-read.json`): a number is accepted as text, written as it was spelled
//! (`1.50` stays `1.50`); text is accepted as a number once trimmed as `String.trim` trims, in any of the
//! decimal digits `Integer.parseInt` reads (`١٢` is twelve); a decimal is accepted as an `int`,
//! truncated; `"TRUE"`, `1` and `"null"` are booleans; an enum is read by its name, trimmed, or by its
//! index, even written as text. **Strict where Jackson is**: a boolean is not a number, an object is
//! not text, an index past the enum's end is refused — and a refusal anywhere refuses the whole body.

use crate::jackson::Refused;
use serde_json::value::RawValue;
use std::borrow::Cow;
use vectispire_domain::java;

/// An object's members, in order, duplicates included, each value as its raw JSON.
pub(crate) type Members<'a> = Vec<(Cow<'a, str>, &'a RawValue)>;

/// A value's JSON shape, the number kept as its token so that it can be read as Jackson reads it.
pub(crate) enum Shape<'a> {
    Null,
    Bool(bool),
    Number(&'a str),
    Text(Cow<'a, str>),
    Object,
    Array,
}

pub(crate) fn shape(raw: &RawValue) -> Result<Shape<'_>, Refused> {
    let text = raw.get();
    Ok(match text.as_bytes().first() {
        Some(b'n') => Shape::Null,
        Some(b't') => Shape::Bool(true),
        Some(b'f') => Shape::Bool(false),
        Some(b'"') => {
            Shape::Text(serde_json::from_str::<Cow<'_, str>>(text).map_err(|error| Refused(error.to_string()))?)
        }
        Some(b'{') => Shape::Object,
        Some(b'[') => Shape::Array,
        _ => Shape::Number(text),
    })
}

fn mismatch<T>(target: &str, shape: &Shape<'_>) -> Result<T, Refused> {
    let found = match shape {
        Shape::Null => "Null",
        Shape::Bool(_) => "Boolean",
        Shape::Number(_) => "Number",
        Shape::Text(_) => "String",
        Shape::Object => "Object",
        Shape::Array => "Array",
    };
    Err(Refused(format!("Cannot deserialize value of type `{target}` from {found} value")))
}

fn is_integer(token: &str) -> bool {
    !token.contains(['.', 'e', 'E'])
}

/// `String`: a scalar's text — a number as it was spelled, a boolean as `true` or `false`.
pub(crate) fn text(raw: &RawValue) -> Result<Option<String>, Refused> {
    match shape(raw)? {
        Shape::Null => Ok(None),
        Shape::Bool(value) => Ok(Some(value.to_string())),
        Shape::Number(token) => Ok(Some(token.to_owned())),
        Shape::Text(value) => Ok(Some(value.into_owned())),
        other => mismatch("java.lang.String", &other),
    }
}

/// `Integer` — `None` for a null, an empty or blank text, and the text `null`.
pub(crate) fn boxed_int(raw: &RawValue) -> Result<Option<i32>, Refused> {
    let out_of_range =
        |token: &str| Refused(format!("Numeric value ({token}) out of range of int (-2147483648 - 2147483647)"));
    match shape(raw)? {
        Shape::Null => Ok(None),
        Shape::Number(token) if is_integer(token) => token.parse::<i32>().map(Some).map_err(|_| out_of_range(token)),
        Shape::Number(token) => {
            // `ACCEPT_FLOAT_AS_INT`: the double, range-checked as a double, then truncated towards zero.
            let value: f64 = token.parse().map_err(|_| out_of_range(token))?;
            if !(-2_147_483_648.0..=2_147_483_647.0).contains(&value) {
                return Err(out_of_range(token));
            }
            #[allow(clippy::cast_possible_truncation)]
            Ok(Some(value.trunc() as i32))
        }
        Shape::Text(value) => {
            let trimmed = java::trim(&value);
            if trimmed.is_empty() || trimmed == "null" {
                return Ok(None);
            }
            java::read_int(trimmed).map(Some).map_err(|_| {
                Refused(format!(
                    "Cannot deserialize value of type `int` from String \"{value}\": not a valid `int` value"
                ))
            })
        }
        other => mismatch("int", &other),
    }
}

/// `int`: as `Integer`, a missing value being 0 (`FAIL_ON_NULL_FOR_PRIMITIVES` is off).
pub(crate) fn int(raw: &RawValue) -> Result<i32, Refused> {
    boxed_int(raw).map(Option::unwrap_or_default)
}

/// `Long`, as [`boxed_int`] reads an `Integer`, within a `long`.
pub(crate) fn boxed_long(raw: &RawValue) -> Result<Option<i64>, Refused> {
    let out_of_range = |token: &str| Refused(format!("Numeric value ({token}) out of range of `long`"));
    match shape(raw)? {
        Shape::Null => Ok(None),
        Shape::Number(token) if is_integer(token) => token.parse::<i64>().map(Some).map_err(|_| out_of_range(token)),
        Shape::Number(token) => {
            let value: f64 = token.parse().map_err(|_| out_of_range(token))?;
            // `Long.MIN_VALUE` and `MAX_VALUE` as doubles, the bounds Jackson checks against.
            #[allow(clippy::cast_precision_loss)]
            if !(i64::MIN as f64..=i64::MAX as f64).contains(&value) {
                return Err(out_of_range(token));
            }
            #[allow(clippy::cast_possible_truncation)]
            Ok(Some(value.trunc() as i64))
        }
        Shape::Text(value) => {
            let trimmed = java::trim(&value);
            if trimmed.is_empty() || trimmed == "null" {
                return Ok(None);
            }
            read_long(trimmed).map(Some).ok_or_else(|| {
                Refused(format!("Cannot deserialize value of type `java.lang.Long` from String \"{value}\""))
            })
        }
        other => mismatch("java.lang.Long", &other),
    }
}

/// `Long.parseLong`: a sign, then at least one digit `Character.digit` reads, within a `long`.
fn read_long(text: &str) -> Option<i64> {
    let (negative, digits) = match text.as_bytes().first()? {
        b'-' => (true, text.get(1..).unwrap_or_default()),
        b'+' => (false, text.get(1..).unwrap_or_default()),
        _ => (false, text),
    };
    if digits.is_empty() {
        return None;
    }
    let mut magnitude: i128 = 0;
    for c in digits.chars() {
        magnitude = magnitude.checked_mul(10)?.checked_add(i128::from(java::digit(c)?))?;
        if magnitude > LONG_MIN_MAGNITUDE {
            return None;
        }
    }
    i64::try_from(if negative { magnitude.checked_neg()? } else { magnitude }).ok()
}

/// A document's root object as members, `None` for the JSON `null`; anything else is no record.
pub(crate) fn root<'a>(text: &'a str, target: &str) -> Result<Option<Members<'a>>, Refused> {
    // The depth was bounded by `jackson::prepare`; `serde_json`'s own limit of 128 is lifted.
    let mut deserializer = serde_json::Deserializer::from_str(text);
    deserializer.disable_recursion_limit();
    let raw = <&RawValue as serde::Deserialize>::deserialize(&mut deserializer)
        .map_err(|error| Refused(error.to_string()))?;
    match shape(raw)? {
        Shape::Null => Ok(None),
        Shape::Object => members_of(raw.get()).map(Some),
        _ => Err(Refused(format!("Cannot construct instance of `{target}`: no delegate- or property-based Creator"))),
    }
}

/// `boolean`: `true` and `false`, any integer (zero is false), the texts `true`, `True`, `TRUE` and
/// their `false` twins, and as false a null, an empty text and the text `null`.
pub(crate) fn boolean(raw: &RawValue) -> Result<bool, Refused> {
    match shape(raw)? {
        Shape::Null => Ok(false),
        Shape::Bool(value) => Ok(value),
        Shape::Number(token) if is_integer(token) => Ok(token.trim_start_matches('-').bytes().any(|b| b != b'0')),
        Shape::Text(value) => match java::trim(&value) {
            "true" | "True" | "TRUE" => Ok(true),
            "false" | "False" | "FALSE" | "" | "null" => Ok(false),
            _ => Err(Refused(format!(
                "Cannot deserialize value of type `boolean` from String \"{value}\": only \"true\"/\"True\"/\"TRUE\" or \"false\"/\"False\"/\"FALSE\" recognized"
            ))),
        },
        other => mismatch("boolean", &other),
    }
}

/// An enum read by Jackson's default: its constant's name, exactly or trimmed; its index, as a number or
/// as a text that starts with a digit and has no leading zero. `names` are the constants in their order.
pub(crate) fn by_name(raw: &RawValue, names: &[&str]) -> Result<Option<usize>, Refused> {
    let unknown = |value: &str| {
        Refused(format!("Cannot deserialize value of type enum from \"{value}\": not one of the values accepted"))
    };
    match shape(raw)? {
        Shape::Null => Ok(None),
        Shape::Number(token) if is_integer(token) => {
            let index = token.parse::<i32>().map_err(|_| unknown(token))?;
            usize::try_from(index).ok().filter(|&index| index < names.len()).map(Some).ok_or_else(|| unknown(token))
        }
        Shape::Text(value) => {
            let trimmed = java::trim(&value);
            if let Some(index) = names.iter().position(|name| *name == trimmed) {
                return Ok(Some(index));
            }
            if trimmed.is_empty() {
                return Err(Refused("Cannot coerce empty String (\"\") to enum value".into()));
            }
            let digit_first = trimmed.starts_with(|c: char| c.is_ascii_digit());
            let leading_zero = trimmed.starts_with('0') && trimmed.len() > 1;
            if digit_first
                && !leading_zero
                && let Some(index) = java::read_int(trimmed)
                    .ok()
                    .and_then(|index| usize::try_from(index).ok())
                    .filter(|&index| index < names.len())
            {
                return Ok(Some(index));
            }
            Err(unknown(&value))
        }
        other => mismatch("enum", &other),
    }
}

/// An enum whose `@JsonCreator` takes the text and answers `null` for a name it does not know —
/// `PluginStep.Signature` and `Refusal`: any scalar is its text, matched exactly.
pub(crate) fn by_wire_name(raw: &RawValue, names: &[&str]) -> Result<Option<usize>, Refused> {
    match shape(raw)? {
        Shape::Object | Shape::Array => Err(Refused("Input mismatch reading Enum: expected a scalar".into())),
        Shape::Null => Ok(None),
        Shape::Bool(value) => Ok(names.iter().position(|name| *name == value.to_string())),
        Shape::Number(token) => Ok(names.iter().position(|name| *name == token)),
        Shape::Text(value) => Ok(names.iter().position(|name| *name == value)),
    }
}

/// A list's elements as raw values, `null` itself being `None`.
pub(crate) fn list<'a>(raw: &'a RawValue, target: &str) -> Result<Option<Vec<&'a RawValue>>, Refused> {
    match shape(raw)? {
        Shape::Null => Ok(None),
        Shape::Array => {
            // Depth was bounded by `jackson::prepare`; `serde_json`'s own limit of 128 would refuse what Jackson reads.
            let mut deserializer = serde_json::Deserializer::from_str(raw.get());
            deserializer.disable_recursion_limit();
            <Vec<&RawValue> as serde::Deserialize>::deserialize(&mut deserializer)
                .map(Some)
                .map_err(|error| Refused(error.to_string()))
        }
        other => mismatch(target, &other),
    }
}

/// An object's members, in order, duplicates included: Jackson reads each of them and keeps the last.
pub(crate) fn members<'a>(raw: &'a RawValue, target: &str) -> Result<Option<Members<'a>>, Refused> {
    match shape(raw)? {
        Shape::Null => Ok(None),
        Shape::Object => members_of(raw.get()).map(Some),
        other => mismatch(target, &other),
    }
}

pub(crate) fn members_of(text: &str) -> Result<Members<'_>, Refused> {
    struct Members;
    impl<'de> serde::de::Visitor<'de> for Members {
        type Value = Vec<(Cow<'de, str>, &'de RawValue)>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an object")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut members = Vec::new();
            while let Some(key) = map.next_key::<Key<'de>>()? {
                members.push((key.0, map.next_value::<&'de RawValue>()?));
            }
            Ok(members)
        }
    }
    let mut deserializer = serde_json::Deserializer::from_str(text);
    deserializer.disable_recursion_limit();
    serde::Deserializer::deserialize_map(&mut deserializer, Members).map_err(|error| Refused(error.to_string()))
}

/// A member's name, borrowed when it holds no escape.
struct Key<'a>(Cow<'a, str>);

impl<'de> serde::Deserialize<'de> for Key<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Name;
        impl<'de> serde::de::Visitor<'de> for Name {
            type Value = Cow<'de, str>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a field name")
            }

            fn visit_borrowed_str<E: serde::de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
                Ok(Cow::Borrowed(value))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(Cow::Owned(value.to_owned()))
            }
        }
        deserializer.deserialize_str(Name).map(Key)
    }
}

/// The last value given to `name` — Jackson reads every occurrence, so each is coerced, and a refusal in
/// an earlier one refuses the body even when a later one would have been accepted.
pub(crate) fn last<'a, T>(
    members: &[(Cow<'_, str>, &'a RawValue)],
    name: &str,
    read: impl Fn(&'a RawValue) -> Result<T, Refused>,
) -> Result<Option<T>, Refused> {
    let mut found = None;
    for (key, value) in members {
        if key == name {
            found = Some(read(value)?);
        }
    }
    Ok(found)
}

/// A `java.time.Duration`, as its two fields: seconds, and a nanosecond adjustment below a second that
/// is never negative — so minus a quarter second is `(-1, 750_000_000)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JavaDuration {
    pub seconds: i64,
    pub nanos: u32,
}

const NANOS: i128 = 1_000_000_000;
/// `Long.MIN_VALUE`'s magnitude, one past `Long.MAX_VALUE`.
const LONG_MIN_MAGNITUDE: i128 = 9_223_372_036_854_775_808;

impl JavaDuration {
    /// `Duration.ofSeconds(seconds, nanoAdjustment)`; `None` where Java throws.
    pub fn of_seconds(seconds: i64, nano_adjustment: i128) -> Option<JavaDuration> {
        let total = i128::from(seconds).checked_add(nano_adjustment.div_euclid(NANOS))?;
        Some(JavaDuration {
            seconds: i64::try_from(total).ok()?,
            nanos: u32::try_from(nano_adjustment.rem_euclid(NANOS)).ok()?,
        })
    }

    fn negated(self) -> Option<JavaDuration> {
        JavaDuration::of_seconds(self.seconds.checked_neg()?, i128::from(self.nanos).wrapping_neg())
    }
}

/// `Duration`, as `DurationDeserializer` reads it with the record's `@JsonFormat(shape = STRING)`: ISO-8601
/// text, trimmed, blank being absent; an integer as seconds; a decimal as seconds through `BigDecimal`.
pub(crate) fn duration(raw: &RawValue) -> Result<Option<JavaDuration>, Refused> {
    match shape(raw)? {
        Shape::Null => Ok(None),
        Shape::Number(token) if is_integer(token) => token
            .parse::<i64>()
            .map(|seconds| Some(JavaDuration { seconds, nanos: 0 }))
            .map_err(|_| Refused(format!("Numeric value ({token}) out of range of long"))),
        Shape::Number(token) => decimal_seconds(token).map(Some),
        Shape::Text(value) => {
            let trimmed = java::trim(&value);
            if trimmed.is_empty() {
                return Ok(None);
            }
            parse_duration(trimmed).map(Some).ok_or_else(|| {
                Refused(format!("Cannot deserialize value of type `java.time.Duration` from String \"{value}\""))
            })
        }
        Shape::Array => Err(Refused("Cannot deserialize value of type `java.time.Duration` from Array value".into())),
        _ => Err(Refused(
            "Unexpected token, expected one of [VALUE_STRING, VALUE_NUMBER_INT, VALUE_NUMBER_FLOAT]".into(),
        )),
    }
}

/// `DecimalUtils.extractSecondsAndNanos`, exactly — including what it does past a `long` of seconds:
/// `BigDecimal.longValue()` keeps the low 64 bits of the integer part (`1e30` is
/// 5,076,944,270,305,263,616 seconds), and `intValue()` the low 32 bits of the nanoseconds left over.
fn decimal_seconds(token: &str) -> Result<JavaDuration, Refused> {
    let unreadable = || Refused(format!("Numeric value ({token}) cannot be read as a Duration"));
    let (negative, unsigned) = match token.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, token),
    };
    let (mantissa, exponent) = match unsigned.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().map_err(|_| unreadable())?),
        None => (unsigned, 0),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    // The number is `digits × 10^-scale`, as `new BigDecimal(token)` holds it.
    let scale = i64::try_from(fraction.len())
        .map_err(|_| unreadable())?
        .checked_sub(i64::from(exponent))
        .ok_or_else(unreadable)?;
    if i32::try_from(scale).is_err() {
        return Err(unreadable());
    }
    let joined = format!("{whole}{fraction}");
    let digits: Vec<u8> = joined.trim_start_matches('0').bytes().map(|b| b.wrapping_sub(b'0')).collect();
    let precision = i64::try_from(digits.len()).map_err(|_| unreadable())?;
    // Zero; no digit left of the point once in nanoseconds (`precision - scale <= 0`); or none left in the
    // low 64 bits (`scale < -63`): zero seconds and zero nanoseconds, all three.
    if digits.is_empty() || precision.saturating_sub(scale.saturating_sub(9)) <= 0 || scale < -63 {
        return Ok(JavaDuration { seconds: 0, nanos: 0 });
    }
    // `digits × 10^(places - scale)` truncated towards zero, kept modulo 2^64.
    let low_bits = |places: i64| -> u64 {
        let exponent = places.saturating_sub(scale);
        let kept = if exponent >= 0 {
            digits.len()
        } else {
            digits.len().saturating_sub(usize::try_from(exponent.saturating_neg()).unwrap_or(usize::MAX))
        };
        let mut value = digits.iter().take(kept).fold(0u64, |acc, &d| acc.wrapping_mul(10).wrapping_add(u64::from(d)));
        for _ in 0..exponent.max(0) {
            value = value.wrapping_mul(10);
        }
        value
    };
    let signed = |magnitude: u64| if negative { magnitude.wrapping_neg() } else { magnitude };
    let seconds = signed(low_bits(0));
    // `nanoseconds - BigDecimal.valueOf(seconds) × 10^9`: an integer of the number's sign, whatever was
    // truncated, so its low 32 bits are those of the same difference taken modulo 2^64.
    let nanos = signed(low_bits(9)).wrapping_sub(seconds.wrapping_mul(1_000_000_000));
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let (seconds, nanos) = (seconds as i64, nanos as u32 as i32);
    JavaDuration::of_seconds(seconds, i128::from(nanos)).ok_or_else(unreadable)
}

/// `Duration.parse`: `[-+]P[nD][T[nH][nM][n[.,f]S]]`, case-insensitive, each number signed, up to nine
/// fraction digits; `None` where Java throws `DateTimeParseException`.
pub fn parse_duration(text: &str) -> Option<JavaDuration> {
    let upper = text.to_ascii_uppercase();
    let (negate, rest) = match upper.as_bytes().first() {
        Some(b'-') => (true, upper.get(1..).unwrap_or_default()),
        Some(b'+') => (false, upper.get(1..).unwrap_or_default()),
        _ => (false, upper.as_str()),
    };
    let mut rest = rest.strip_prefix('P')?;
    let days = unit(&mut rest, 'D')?;
    let (mut hours, mut minutes, mut seconds) = (None, None, None);
    let mut nanos: i128 = 0;
    if let Some(time) = rest.strip_prefix('T') {
        rest = time;
        hours = unit(&mut rest, 'H')?;
        minutes = unit(&mut rest, 'M')?;
        if let Some(number) = signed_digits(rest) {
            let after = rest.get(number.len()..).unwrap_or_default();
            let (fraction, tail) = match after.strip_prefix(['.', ',']) {
                Some(part) => {
                    let count = part.bytes().take_while(u8::is_ascii_digit).count();
                    part.split_at_checked(count).unwrap_or((part, ""))
                }
                None => ("", after),
            };
            if let Some(tail) = tail.strip_prefix('S') {
                if fraction.len() > 9 {
                    return None;
                }
                seconds = Some(number.parse::<i64>().ok()?);
                if !fraction.is_empty() {
                    nanos = format!("{fraction:0<9}").parse::<i128>().ok()?;
                    // The fraction takes the seconds' sign: `PT-0.5S` is minus half a second.
                    if number.starts_with('-') {
                        nanos = nanos.wrapping_neg();
                    }
                }
                rest = tail;
            }
        }
        if hours.is_none() && minutes.is_none() && seconds.is_none() {
            return None;
        }
    }
    if !rest.is_empty() || (days.is_none() && hours.is_none() && minutes.is_none() && seconds.is_none()) {
        return None;
    }
    // Summed from the seconds up, as `Duration.create` nests its `addExact`s: where the sum overflows on
    // the way decides whether Java refuses it.
    let total = seconds
        .unwrap_or(0)
        .checked_add(minutes.unwrap_or(0).checked_mul(60)?)?
        .checked_add(hours.unwrap_or(0).checked_mul(3_600)?)?
        .checked_add(days.unwrap_or(0).checked_mul(86_400)?)?;
    let duration = JavaDuration::of_seconds(total, nanos)?;
    if negate { duration.negated() } else { Some(duration) }
}

/// A `[-+]?[0-9]+` at the start of `text`.
fn signed_digits(text: &str) -> Option<&str> {
    let sign = usize::from(matches!(text.as_bytes().first(), Some(b'-' | b'+')));
    let digits = text.as_bytes().get(sign..)?.iter().take_while(|b| b.is_ascii_digit()).count();
    text.get(..sign.saturating_add(digits)).filter(|_| digits > 0)
}

/// A signed number followed by `unit`, consumed; `Some(None)` when there is none, `None` when the number
/// does not fit a `long`.
fn unit(rest: &mut &str, unit: char) -> Option<Option<i64>> {
    let Some(number) = signed_digits(rest) else { return Some(None) };
    if !rest.get(number.len()..).is_some_and(|after| after.starts_with(unit)) {
        return Some(None);
    }
    let value = number.parse::<i64>().ok()?;
    *rest = rest.get(number.len().saturating_add(1)..).unwrap_or_default();
    Some(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(text: &str) -> Box<RawValue> {
        RawValue::from_string(text.to_owned())
            .unwrap_or_else(|_| RawValue::from_string("null".into()).unwrap_or_default())
    }

    #[test]
    fn a_duration_reads_as_java_s() {
        let d = |seconds, nanos| Some(JavaDuration { seconds, nanos });
        assert_eq!(parse_duration("PT12.345S"), d(12, 345_000_000));
        assert_eq!(parse_duration("-PT-1S"), d(1, 0));
        assert_eq!(parse_duration("PT-0.000000001S"), d(-1, 999_999_999));
        assert_eq!(parse_duration("P1DT"), None);
        assert_eq!(parse_duration("pt1h2m3.25s"), d(3_723, 250_000_000));
        assert_eq!(decimal_seconds("1e30").ok(), d(5_076_944_270_305_263_616, 0));
        assert_eq!(decimal_seconds("-1.1234567891").ok(), d(-2, 876_543_211));
    }

    #[test]
    fn coercions_hold_to_their_shapes() {
        assert_eq!(int(&raw("\" 12 \"")).ok(), Some(12));
        assert_eq!(boolean(&raw("\"null\"")).ok(), Some(false));
        assert_eq!(by_name(&raw("\" 1\""), &["A", "B"]).ok(), Some(Some(1)));
        assert!(by_name(&raw("\"01\""), &["A", "B"]).is_err());
        assert_eq!(text(&raw("1.50")).ok(), Some(Some("1.50".into())));
    }
}
