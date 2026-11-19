//! Jackson's `JsonNode` reading, where the Java executor reads the API server's answers with it: a pod's status, an
//! exec's status document. The answers are the API server's, but read leniently as Jackson reads them — a missing
//! member is a default, an object iterated is its values — so that the two agents decide the same from the same pod.

use serde_json::Value;

/// `node.path(field)`.
pub fn path<'a>(node: Option<&'a Value>, field: &str) -> Option<&'a Value> {
    vectispire_domain::java::path(node, field)
}

/// `asText()`: `""` for a missing node, `"null"` for a null one.
pub fn text(node: Option<&Value>) -> String {
    vectispire_domain::checklists::jackson::as_text(node)
}

/// `asText(default)`: the default for a missing or null node.
pub fn text_or(node: Option<&Value>, default: &str) -> String {
    vectispire_domain::java::as_text(node, Some(default)).unwrap_or_default()
}

/// `asInt()` — and `asInt(0)`, which is the same answer.
pub fn int(node: Option<&Value>) -> i32 {
    vectispire_domain::checklists::jackson::as_int(node)
}

/// `node.has(field)`: a member of that name, whatever its value, null included.
pub fn has(node: Option<&Value>, field: &str) -> bool {
    node.and_then(Value::as_object).is_some_and(|object| object.contains_key(field))
}

/// What `for (JsonNode child : node)` visits: an array's elements, an object's values, nothing for anything else.
pub fn children(node: Option<&Value>) -> Vec<&Value> {
    match node {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(Value::Object(members)) => members.values().collect(),
        _ => Vec::new(),
    }
}

/// `ObjectMapper.readTree(text)`: the first value of the text, whatever follows it — Jackson does not refuse trailing
/// content by default — or `None` when there is none to read.
pub fn read_tree(text: &[u8]) -> Option<Value> {
    serde_json::Deserializer::from_slice(text).into_iter::<Value>().next()?.ok()
}
