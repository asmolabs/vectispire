//! Query parameters as Spring MVC binds them to `@RequestParam` — the audit trail's filters and its window.
//!
//! **Every value counts, not the first.** A `String` parameter sent twice reaches the controller as the values joined
//! by a comma (`ArrayToStringConverter`); an `int` takes the first (`ArrayToObjectConverter`). An empty value is the
//! declared default — but only an empty one: `" "` is converted, and refused, as `NumberUtils.parseNumber` refuses it.

use http::StatusCode;
use vectispire_cp_http::Problem;
use vectispire_domain::java;

/// `TypeMismatchException`'s problem detail, as Spring's message source words it.
fn mismatch(name: &str, value: &str) -> Problem {
    Problem::handler(StatusCode::BAD_REQUEST, format!("Failed to convert '{name}' with value: '{value}'"))
}

/// `NumberUtils.parseNumber(text, Integer.class)`: white space removed anywhere, a hexadecimal form (`0x`, `0X`, `#`,
/// signed) read by `Integer.decode`, anything else by `Integer.valueOf` — which takes any Unicode decimal digit.
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

/// Every value of `name`, decoded as a form is (`+` is a space), in the order sent.
fn values(query: Option<&str>, name: &str) -> Vec<String> {
    let Some(query) = query else { return Vec::new() };
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(key) == name).then(|| decode(value))
        })
        .collect()
}

fn decode(text: &str) -> String {
    percent_encoding::percent_decode_str(&text.replace('+', " ")).decode_utf8_lossy().into_owned()
}

/// An optional `String` parameter: absent is `None`; sent more than once, the values joined by commas.
pub fn text(query: Option<&str>, name: &str) -> Option<String> {
    let all = values(query, name);
    if all.is_empty() { None } else { Some(all.join(",")) }
}

/// An `int` parameter with `defaultValue`: absent or empty is the default, anything else converted or refused.
pub fn int_or(query: Option<&str>, name: &str, default: i32) -> Result<i32, Problem> {
    let Some(first) = values(query, name).into_iter().next() else {
        return Ok(default);
    };
    if first.is_empty() {
        return Ok(default);
    }
    java_int(&first).ok_or_else(|| mismatch(name, &first))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn an_int_reads_as_spring_converts_it() {
        assert_eq!(java_int("42"), Some(42));
        assert_eq!(java_int(" 4 2 "), Some(42), "white space anywhere is removed");
        assert_eq!(java_int("0x10"), Some(16));
        assert_eq!(java_int("#10"), Some(16));
        assert_eq!(java_int("-0x10"), Some(-16));
        assert_eq!(java_int("+7"), Some(7));
        assert_eq!(java_int("٤٢"), Some(42), "Integer.valueOf reads any Unicode decimal digit");
        assert_eq!(java_int("-2147483648"), Some(i32::MIN));
        assert_eq!(java_int("2147483648"), None, "past Integer.MAX_VALUE");
        assert_eq!(java_int("4294967297"), None, "refused, never wrapped");
        assert_eq!(java_int("-4294967297"), None, "refused, never wrapped");
        assert_eq!(java_int("abc"), None);
        assert_eq!(java_int(""), None);
        assert_eq!(java_int("--1"), None);
    }

    #[test]
    fn an_int_with_a_default_takes_it_when_absent_or_empty_only() {
        let read = |query: Option<&str>| int_or(query, "limit", 50).map_err(|p| p.detail().to_owned());
        assert_eq!(read(None), Ok(50));
        assert_eq!(read(Some("offset=3")), Ok(50));
        assert_eq!(read(Some("limit=")), Ok(50));
        assert_eq!(read(Some("limit")), Ok(50));
        assert_eq!(read(Some("limit=7&limit=9")), Ok(7), "the first value");
        assert_eq!(read(Some("limit=%20")), Err("Failed to convert 'limit' with value: ' '".to_owned()));
        assert_eq!(read(Some("limit=ten")), Err("Failed to convert 'limit' with value: 'ten'".to_owned()));
    }

    #[test]
    fn a_text_is_every_value_joined_and_decoded() {
        assert_eq!(text(None, "search"), None);
        assert_eq!(text(Some("search="), "search"), Some(String::new()));
        assert_eq!(text(Some("search=a+b%2Fc"), "search"), Some("a b/c".to_owned()));
        assert_eq!(text(Some("search=a&x=1&search=b"), "search"), Some("a,b".to_owned()));
        assert_eq!(text(Some("user_id=u"), "search"), None);
    }
}
