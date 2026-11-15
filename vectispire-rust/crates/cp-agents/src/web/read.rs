//! The claim's `wait`, read as Spring MVC binds `@RequestParam(defaultValue = "0") int wait`: by
//! `NumberUtils.parseNumber`, refused in `TypeMismatchException`'s sentence. The same rules as `cp-scanning`'s
//! reader, which is that module's own; a route's reader is not shared across modules (`web` is never `pub`).
//!
//! Read as 0 before, whatever it said: an agent sending `wait=thirty` polled without waiting, in a tight loop, where
//! Java tells it at once that it is misconfigured.

use http::StatusCode;
use vectispire_cp_http::Problem;
use vectispire_domain::java;

fn mismatch(name: &str, value: &str) -> Problem {
    Problem::handler(StatusCode::BAD_REQUEST, format!("Failed to convert '{name}' with value: '{value}'"))
}

/// `NumberUtils.parseNumber(text, Integer.class)`: white space removed anywhere, a hexadecimal form read by
/// `Integer.decode`, anything else by `Integer.valueOf`, which takes any Unicode decimal digit.
fn java_int(text: &str) -> Option<i32> {
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
    // Accumulated negatively, as `Integer.parseInt` does, so that `Integer.MIN_VALUE` reads.
    let mut value: i32 = 0;
    for c in digits.chars() {
        let digit = if radix == 10 { java::digit(c)? } else { c.to_digit(16)? };
        value = value.checked_mul(radix)?.checked_sub(i32::try_from(digit).ok()?)?;
    }
    if negative { Some(value) } else { value.checked_neg() }
}

/// `wait`: absent or empty is the default, 0; the first value counts; anything `int` cannot hold is a 400.
pub fn wait(query: Option<&str>) -> Result<i32, Problem> {
    match first_value(query, "wait") {
        None => Ok(0),
        Some(raw) if raw.is_empty() => Ok(0),
        Some(raw) => java_int(&raw).ok_or_else(|| mismatch("wait", &raw)),
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

#[cfg(test)]
mod tests {
    use super::wait;

    #[test]
    fn wait_is_read_as_spring_binds_an_int() {
        assert_eq!(wait(None).ok(), Some(0));
        assert_eq!(wait(Some("wait=")).ok(), Some(0));
        assert_eq!(wait(Some("other=1")).ok(), Some(0));
        assert_eq!(wait(Some("wait=30")).ok(), Some(30));
        assert_eq!(wait(Some("wait=+5&wait=9")).ok(), Some(5));
        assert_eq!(wait(Some("wait=0x10")).ok(), Some(16));
        assert_eq!(wait(Some("wait=%2030%20")).ok(), Some(30));
        assert_eq!(wait(Some("wait=-2147483648")).ok(), Some(i32::MIN));
        for refused in ["wait=thirty", "wait=2147483648", "wait=1.5", "wait=--1", "wait=0x"] {
            let problem = wait(Some(refused)).err().unwrap_or_else(|| panic!("{refused} is refused"));
            assert_eq!(problem.status().as_u16(), 400, "{refused}");
        }
        let problem = wait(Some("wait=thirty")).err().unwrap_or_else(|| panic!("refused"));
        assert_eq!(problem.detail(), "Failed to convert 'wait' with value: 'thirty'");
    }
}
