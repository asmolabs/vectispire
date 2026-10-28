//! Query and path variable readers matching Spring MVC coercion and error messages.

use http::StatusCode;
use vectispire_cp_http::Problem;
use vectispire_domain::java;

fn mismatch(name: &str, value: &str) -> Problem {
    Problem::handler(StatusCode::BAD_REQUEST, format!("Failed to convert '{name}' with value: '{value}'"))
}

fn trim_all_whitespace(text: &str) -> String {
    text.chars().filter(|c| !java::is_whitespace(*c)).collect()
}

fn java_long(text: &str) -> Option<i64> {
    let trimmed = trim_all_whitespace(text);
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
    let mut value: i64 = 0;
    for c in digits.chars() {
        let digit = if radix == 10 { java::digit(c)? } else { c.to_digit(16)? };
        value = value.checked_mul(radix)?.checked_sub(i64::from(digit))?;
    }
    if negative { Some(value) } else { value.checked_neg() }
}

pub fn path_long(name: &str, value: &str) -> Result<i64, Problem> {
    java_long(value).ok_or_else(|| mismatch(name, value))
}

pub fn query_long(query: Option<&str>, name: &str) -> Result<Option<i64>, Problem> {
    let Some(raw) = first_value(query, name) else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    java_long(&raw).map(Some).ok_or_else(|| mismatch(name, &raw))
}

pub fn query_int(query: Option<&str>, name: &str) -> Result<Option<i32>, Problem> {
    let Some(raw) = first_value(query, name) else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    match java_long(&raw).and_then(|val| i32::try_from(val).ok()) {
        Some(v) => Ok(Some(v)),
        None => Err(mismatch(name, &raw)),
    }
}

pub fn query_bool(query: Option<&str>, name: &str, default: bool) -> Result<bool, Problem> {
    let Some(raw) = first_value(query, name) else {
        return Ok(default);
    };
    if raw.trim().is_empty() {
        return Ok(default);
    }
    match raw.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(mismatch(name, &raw)),
    }
}

pub fn query_string(query: Option<&str>, name: &str) -> Option<String> {
    let raw = first_value(query, name)?;
    if raw.is_empty() { None } else { Some(raw) }
}

fn first_value(query: Option<&str>, name: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (decode(key) == name).then(|| decode(value))
    })
}

fn decode(text: &str) -> String {
    let unescaped = text.replace('+', " ");
    percent_encoding::percent_decode_str(&unescaped).decode_utf8_lossy().into_owned()
}
