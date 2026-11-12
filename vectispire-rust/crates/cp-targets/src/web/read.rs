//! What a route reads from a request, the way Spring MVC and Jackson read it: path variables and query parameters
//! converted as `NumberUtils.parseNumber` and `StringToUUIDConverter` convert them, refused in Spring's sentence; and a
//! body read field by field as Jackson binds a record — unknown fields ignored, a scalar coerced to the field's type
//! where Jackson coerces it, anything else the one 400 sentence `ApiExceptionHandler` answers.

use http::StatusCode;
use serde_json::{Map, Value};
use uuid::Uuid;
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

/// A `UUID` path variable: `UUID.fromString(source.trim())`.
pub fn path_uuid(name: &str, value: &str) -> Result<Uuid, Problem> {
    crate::repositories::java_uuid(java::trim(value)).ok_or_else(|| mismatch(name, value))
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

/// A body bound to a record: its fields, or the 400 for a body that is not a JSON object — `null` included, which
/// Spring answers as a missing body.
pub struct Fields(Map<String, Value>);

impl Fields {
    pub fn of(body: Value) -> Result<Fields, Problem> {
        match body {
            Value::Object(fields) => Ok(Fields(fields)),
            _ => Err(Problem::handler(StatusCode::BAD_REQUEST, UNREADABLE)),
        }
    }

    /// A `String` component: absent or `null` is `None`; a number or a boolean is its text, as Jackson coerces a
    /// scalar into a string; an array or an object refuses the body.
    pub fn text(&self, name: &str) -> Result<Option<String>, Problem> {
        match self.0.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(text)) => Ok(Some(text.clone())),
            Some(Value::Number(number)) => Ok(Some(number.to_string())),
            Some(Value::Bool(flag)) => Ok(Some(flag.to_string())),
            Some(_) => Err(unreadable()),
        }
    }

    /// An `Integer` component: an integral number in range, or a string Jackson reads as one (an empty string is
    /// `null`); a decimal is truncated, as Jackson's default float-to-int coercion does.
    pub fn int(&self, name: &str) -> Result<Option<i32>, Problem> {
        match self.0.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Number(number)) => {
                if let Some(value) = number.as_i64() {
                    return i32::try_from(value).map(Some).map_err(|_| unreadable());
                }
                match number.as_f64() {
                    Some(value) if value.is_finite() && value.abs() < 2_147_483_648.0 => {
                        #[allow(clippy::cast_possible_truncation)] // In range, checked on the line above.
                        Ok(Some(value.trunc() as i32))
                    }
                    _ => Err(unreadable()),
                }
            }
            Some(Value::String(text)) => {
                let trimmed = java::trim(text);
                if trimmed.is_empty() {
                    return Ok(None);
                }
                java::parse_int(trimmed).map(Some).map_err(|_| unreadable())
            }
            Some(_) => Err(unreadable()),
        }
    }

    /// A `Long` component.
    pub fn long(&self, name: &str) -> Result<Option<i64>, Problem> {
        match self.0.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Number(number)) => number.as_i64().map(Some).ok_or_else(unreadable),
            Some(Value::String(text)) => {
                let trimmed = java::trim(text);
                if trimmed.is_empty() {
                    return Ok(None);
                }
                java_long(trimmed).map(Some).ok_or_else(unreadable)
            }
            Some(_) => Err(unreadable()),
        }
    }

    /// A `Boolean` component: a boolean, or the strings `true` and `false` (an empty string is `null`).
    pub fn flag(&self, name: &str) -> Result<Option<bool>, Problem> {
        match self.0.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bool(flag)) => Ok(Some(*flag)),
            Some(Value::String(text)) => match java::trim(text) {
                "" => Ok(None),
                "true" => Ok(Some(true)),
                "false" => Ok(Some(false)),
                _ => Err(unreadable()),
            },
            Some(_) => Err(unreadable()),
        }
    }
}

fn unreadable() -> Problem {
    Problem::handler(StatusCode::BAD_REQUEST, UNREADABLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_variable_reads_as_spring_converts_it() {
        assert_eq!(java_long("42"), Some(42));
        assert_eq!(java_long(" 4 2 "), Some(42), "white space anywhere is removed");
        assert_eq!(java_long("0x10"), Some(16));
        assert_eq!(java_long("#10"), Some(16));
        assert_eq!(java_long("-0x10"), Some(-16));
        assert_eq!(java_long("+7"), Some(7));
        assert_eq!(java_long("٤٢"), Some(42), "Long.valueOf reads any Unicode decimal digit");
        assert_eq!(java_long("-9223372036854775808"), Some(i64::MIN));
        assert_eq!(java_long("9223372036854775808"), None);
        assert_eq!(java_long("abc"), None);
        assert_eq!(java_long(""), None);
        assert_eq!(java_long("--1"), None);
    }

    #[test]
    fn a_query_parameter_is_its_first_value_decoded() {
        assert_eq!(query_int(Some("limit=5&limit=7"), "limit").map_err(|p| p.detail().to_owned()), Ok(Some(5)));
        assert_eq!(query_int(Some("limit="), "limit").map_err(|p| p.detail().to_owned()), Ok(None));
        assert_eq!(query_int(None, "limit").map_err(|p| p.detail().to_owned()), Ok(None));
        assert_eq!(
            query_int(Some("limit=x+y"), "limit").map_err(|p| p.detail().to_owned()),
            Err("Failed to convert 'limit' with value: 'x y'".to_owned())
        );
    }
}
