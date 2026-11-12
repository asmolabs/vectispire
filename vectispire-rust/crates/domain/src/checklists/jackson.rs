//! The `JsonNode` accessors a stored form is read back with, as Jackson answers them: a stored row is read
//! leniently — `path(…).asInt()` on a missing field is 0, on a numeric text its number — and a reader that refused
//! where Jackson coerces would make a row Java reads unreadable here.

use serde_json::Value;

/// `node.get(name)`, absent for a non-object.
pub fn get<'a>(node: &'a Value, name: &str) -> Option<&'a Value> {
    node.as_object()?.get(name)
}

/// The `text(node, name)` helper of the stored forms: absent for a missing or null member, otherwise `asText()`.
pub fn text(node: &Value, name: &str) -> Option<String> {
    match get(node, name) {
        None | Some(Value::Null) => None,
        Some(value) => Some(as_text(Some(value))),
    }
}

/// `path(name).asText()`: `""` for a missing member, `"null"` for a null one, a container's `""`.
pub fn as_text(node: Option<&Value>) -> String {
    match node {
        None => String::new(),
        Some(Value::Null) => "null".to_owned(),
        Some(other) => crate::java::as_text(Some(other), None).unwrap_or_default(),
    }
}

/// `asLong()`: an integral number's value, a fraction truncated, a numeric text parsed, a boolean 1 or 0, else 0.
pub fn as_long(node: Option<&Value>) -> i64 {
    match node {
        Some(Value::Number(number)) => number.as_i64().or_else(|| number.as_f64().map(truncate)).unwrap_or(0),
        Some(Value::String(text)) => {
            let text = text.trim();
            text.parse::<i64>().ok().or_else(|| text.parse::<f64>().ok().map(truncate)).unwrap_or(0)
        }
        Some(Value::Bool(flag)) => i64::from(*flag),
        _ => 0,
    }
}

/// `asInt()`: [`as_long`] narrowed as Java's `(int)` cast narrows — its low 32 bits.
pub fn as_int(node: Option<&Value>) -> i32 {
    const WORD: i64 = 4_294_967_296;
    let low = as_long(node).rem_euclid(WORD);
    i32::try_from(if low >= 2_147_483_648 { low.wrapping_sub(WORD) } else { low }).unwrap_or(0)
}

/// `asBoolean()`: a boolean's value, a number other than zero, the text `true` (trimmed), else false.
pub fn as_boolean(node: Option<&Value>) -> bool {
    match node {
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|value| value != 0.0),
        Some(Value::String(text)) => text.trim() == "true",
        _ => false,
    }
}

/// `(long) double`: toward zero, saturating at the ends, NaN as 0 — through its text, which needs no cast.
fn truncate(value: f64) -> i64 {
    if value.is_nan() {
        return 0;
    }
    format!("{:.0}", value.trunc()).parse().unwrap_or(if value < 0.0 { i64::MIN } else { i64::MAX })
}

/// `ObjectMapper.readTree(String)`: the first value of the text — what follows it is not read, as Jackson's default
/// leaves it — `None` for a text holding none (Jackson's `MissingNode`), and an error for one that does not parse.
pub fn read_tree(text: &str) -> Result<Option<Value>, serde_json::Error> {
    serde_json::Deserializer::from_str(text).into_iter::<Value>().next().transpose()
}
