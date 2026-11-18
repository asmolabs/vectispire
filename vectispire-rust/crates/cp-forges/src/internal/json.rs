//! Jackson's `JsonNode` readings, for what a forge answers: `path(...)` on a missing member is a missing node, and
//! `asText`, `asBoolean`, `asLong` coerce as Jackson does — the adapters were written against those, and a forge
//! that sends a number as text is read the same way here.

use serde_json::Value;

/// `node.path(name)`: the member, or `None` — Jackson's missing node.
pub(crate) fn path<'a>(node: Option<&'a Value>, name: &str) -> Option<&'a Value> {
    node.and_then(|node| node.get(name))
}

/// `isTextual()` then `asText()`: the member's text when it is a string.
pub(crate) fn text<'a>(node: Option<&'a Value>, name: &str) -> Option<&'a str> {
    path(node, name).and_then(Value::as_str)
}

/// `textValue()`: a string member's text, `None` for anything else.
pub(crate) fn text_value(node: Option<&Value>) -> Option<&str> {
    node.and_then(Value::as_str)
}

/// `asText()`: a string's text, a number's or a boolean's spelling, `""` for null, an object, an array or nothing.
pub(crate) fn as_text(node: Option<&Value>) -> String {
    match node {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        _ => String::new(),
    }
}

/// `asBoolean(default)`: a boolean's value, a number non-zero, the text "true" or "false"; otherwise `default`.
pub(crate) fn as_boolean(node: Option<&Value>, default: bool) -> bool {
    match node {
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(number)) => number.as_i64().map_or(default, |value| value != 0),
        Some(Value::String(text)) => match text.trim() {
            "true" => true,
            "false" => false,
            _ => default,
        },
        _ => default,
    }
}

/// The elements of an array member; empty for anything else.
pub(crate) fn elements<'a>(node: Option<&'a Value>, name: &str) -> &'a [Value] {
    path(node, name).and_then(Value::as_array).map_or(&[], Vec::as_slice)
}
