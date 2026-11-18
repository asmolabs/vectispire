//! What the ticket routes read from a request (as `cp-access`' and `cp-targets`' routes read theirs), the way Spring MVC and Jackson read it: path variables and query parameters
//! converted as `NumberUtils.parseNumber` and `StringToUUIDConverter` convert them, refused in Spring's sentence; and a
//! body read field by field as Jackson binds a record — unknown fields ignored, a scalar coerced to the field's type
//! where Jackson coerces it, anything else the one 400 sentence `ApiExceptionHandler` answers.

use http::StatusCode;
use serde_json::{Map, Value};
use vectispire_cp_http::Problem;
use vectispire_domain::java;

/// `ApiExceptionHandler.handleHttpMessageNotReadable`'s sentence.
pub const UNREADABLE: &str = "The request body could not be read: it is not JSON, or not the shape this route expects.";

/// `TypeMismatchException`'s problem detail, as Spring's message source words it.
fn mismatch(name: &str, value: &str) -> Problem {
    Problem::handler(StatusCode::BAD_REQUEST, format!("Failed to convert '{name}' with value: '{value}'"))
}

/// `StringUtils.trimAllWhitespace`: every `Character.isWhitespace` character removed, wherever it stands.
fn trim_all_whitespace(text: &str) -> String {
    text.chars().filter(|c| !java::is_whitespace(*c)).collect()
}

/// `NumberUtils.parseNumber(text, Long.class)`: white space removed anywhere, a hexadecimal form (`0x`, `0X`, `#`,
/// signed) read by `Long.decode`, anything else by `Long.valueOf` — which takes any Unicode decimal digit.
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

/// An optional `Integer` query parameter: absent or empty is `None`; the first value counts, as Spring binds one.
pub fn query_int(query: Option<&str>, name: &str) -> Result<Option<i32>, Problem> {
    let Some(raw) = first_value(query, name) else {
        return Ok(None);
    };
    if raw.is_empty() {
        return Ok(None);
    }
    match java_long(&raw).and_then(|value| i32::try_from(value).ok()) {
        Some(value) => Ok(Some(value)),
        None => Err(mismatch(name, &raw)),
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

/// The raw body of a route that `consumes` it, under the chain's ceiling: the 413 past it, Spring's 400 for a body
/// that cannot be read.
pub async fn raw_body(body: axum::body::Body) -> Result<Vec<u8>, Problem> {
    use http_body_util::BodyExt as _;
    match body.collect().await {
        Ok(collected) => Ok(collected.to_bytes().to_vec()),
        Err(error) => match vectispire_cp_http::limits::find_too_large(&error) {
            Some(too_large) => Err(Problem::handler(
                StatusCode::PAYLOAD_TOO_LARGE,
                vectispire_cp_http::limits::too_large_detail(too_large.ceiling),
            )),
            None => Err(Problem::handler(StatusCode::BAD_REQUEST, UNREADABLE)),
        },
    }
}

fn unreadable() -> Problem {
    Problem::handler(StatusCode::BAD_REQUEST, UNREADABLE)
}

// ------------------------------------------------------------------ a record's components, as Jackson binds them

/// A `String` component: a string, or a number's or boolean's text; an array or an object refuses the body.
pub fn text(value: Option<&Value>) -> Result<Option<String>, Problem> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(Value::Number(number)) => Ok(Some(number.to_string())),
        Some(Value::Bool(flag)) => Ok(Some(flag.to_string())),
        Some(_) => Err(unreadable()),
    }
}

/// A record body: its fields, or the 400 for a body that is not a JSON object (`null` is a missing body).
pub fn object(body: &Value) -> Result<&Map<String, Value>, Problem> {
    match body {
        Value::Object(fields) => Ok(fields),
        _ => Err(unreadable()),
    }
}
