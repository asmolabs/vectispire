//! A scanner's JSON on stdout — `ContainerRunner.parseJson`.
//!
//! Shared by every scanner that prints its report rather than writing a file. Whitespace is Java's,
//! and a document that does not parse is `None` — the caller decides whether that means "absent".

use crate::failure::ScannerError;
use crate::jackson;
use serde_json::Value;
use vectispire_container::ContainerResult;

/// The JSON document on `result`'s stdout, `Ok(None)` when it is blank or not JSON; an error when the
/// exit code is not one of `accepted`.
pub fn parse_json(result: &ContainerResult, label: &str, accepted: &[i64]) -> Result<Option<Value>, ScannerError> {
    if !accepted.contains(&result.exit_code) {
        return Err(ScannerError::exited(label, result.exit_code, &result.stderr));
    }
    let payload = result.stdout.trim_matches(jackson::is_java_whitespace);
    if payload.is_empty() {
        return Ok(None);
    }
    Ok(jackson::read_tree(payload))
}

/// `for (JsonNode child : node)`: an array's elements, an object's values in their order, nothing
/// for anything else — a `failed_checks` written as an object is read, not skipped.
pub fn children(node: Option<&Value>) -> Vec<&Value> {
    match node {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(Value::Object(members)) => members.values().collect(),
        _ => Vec::new(),
    }
}

/// `node.path(index)`: an array's element, absent for anything else.
pub fn index(node: Option<&Value>, at: usize) -> Option<&Value> {
    match node {
        Some(Value::Array(items)) => items.get(at),
        _ => None,
    }
}

/// `node.path(field)` on what may already be absent.
pub fn path<'a>(node: Option<&'a Value>, field: &str) -> Option<&'a Value> {
    node.and_then(|value| jackson::path(value, field))
}

/// `isTextual() ? asText() : null`.
pub fn text_or_none(node: Option<&Value>) -> Option<String> {
    match node {
        Some(Value::String(text)) => Some(text.clone()),
        _ => None,
    }
}

/// `asText(null)`: as [`jackson::as_text`], with no text for null or absent.
pub fn as_text_or_none(node: Option<&Value>) -> Option<String> {
    match node {
        None | Some(Value::Null) => None,
        other => Some(jackson::as_text(other, "")),
    }
}

/// `size()` of an array, zero for anything else — as the Java side asks it after `isArray()`.
pub fn array_len(node: Option<&Value>) -> usize {
    match node {
        Some(Value::Array(items)) => items.len(),
        _ => 0,
    }
}
