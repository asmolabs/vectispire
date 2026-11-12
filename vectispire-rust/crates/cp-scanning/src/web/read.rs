//! What a scan route reads from a request, as Spring MVC converts it: a path variable or a query parameter read by
//! `NumberUtils.parseNumber`, refused in Spring's sentence. The same rules as `cp-targets`' routes, whose reader is
//! that module's own.

use http::StatusCode;
use vectispire_cp_http::Problem;
use vectispire_domain::java;

/// `TypeMismatchException`'s problem detail.
fn mismatch(name: &str, value: &str) -> Problem {
    Problem::handler(StatusCode::BAD_REQUEST, format!("Failed to convert '{name}' with value: '{value}'"))
}

/// `NumberUtils.parseNumber(text, Long.class)`: white space removed anywhere, a hexadecimal form read by
/// `Long.decode`, anything else by `Long.valueOf`, which takes any Unicode decimal digit.
fn java_long(text: &str) -> Option<i64> {
    let trimmed: String = text.chars().filter(|c| !java::is_whitespace(*c)).collect();
    let (negative, unsigned) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(&trimmed)),
    };
    let hex =
        unsigned.strip_prefix("0x").or_else(|| unsigned.strip_prefix("0X")).or_else(|| unsigned.strip_prefix('#'));
    let (digits, radix) = match hex {
        Some(digits) => (digits, 16),
        None => (unsigned, 10),
    };
    if digits.is_empty() || digits.starts_with(['-', '+']) {
        return None;
    }
    // Accumulated negatively, as `Long.parseLong` does, so that `Long.MIN_VALUE` reads.
    let mut value: i64 = 0;
    for c in digits.chars() {
        let digit = if radix == 10 { java::digit(c)? } else { c.to_digit(16)? };
        value = value.checked_mul(radix)?.checked_sub(i64::from(digit))?;
    }
    if negative { Some(value) } else { value.checked_neg() }
}

/// A `long` path variable.
pub fn path_long(name: &str, value: &str) -> Result<i64, Problem> {
    java_long(value).ok_or_else(|| mismatch(name, value))
}

/// An optional `Long` query parameter: absent or empty is `None`; the first value counts.
pub fn query_long(query: Option<&str>, name: &str) -> Result<Option<i64>, Problem> {
    match first_value(query, name) {
        None => Ok(None),
        Some(raw) if raw.is_empty() => Ok(None),
        Some(raw) => java_long(&raw).map(Some).ok_or_else(|| mismatch(name, &raw)),
    }
}

/// An optional `Integer` query parameter.
pub fn query_int(query: Option<&str>, name: &str) -> Result<Option<i32>, Problem> {
    match query_long(query, name) {
        Ok(Some(value)) => {
            i32::try_from(value).map(Some).map_err(|_| mismatch(name, &first_value(query, name).unwrap_or_default()))
        }
        Ok(None) => Ok(None),
        Err(problem) => Err(problem),
    }
}

/// The first value of a query parameter, decoded as a form is (`+` is a space).
fn first_value(query: Option<&str>, name: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (decode(key) == name).then(|| decode(value))
    })
}

fn decode(text: &str) -> String {
    percent_encoding::percent_decode_str(&text.replace('+', " ")).decode_utf8_lossy().into_owned()
}
