//! The payload as `enqueue` stores it — Java's `json.valueToTree(payload)`, `put("message_id", id)`, `toString()`.
//!
//! **The message id goes inside the payload** because delivery is at least once: the POST can succeed and the write
//! marking it sent can fail, and the receiver is the only place that ambiguity can be resolved, so it has to be told
//! which message this is. A payload that already carries a `message_id` has it replaced **where it stands**, as
//! `ObjectNode.put` replaces a member; a new one is appended last. `serde_json`'s `preserve_order` (on for the whole
//! workspace) keeps the members in the caller's order, as the tree does.

use std::io;

use serde::Serialize;
use serde_json::ser::{CharEscape, Formatter};
use serde_json::{Map, Value};
use uuid::Uuid;

/// Why a payload could not be stored.
#[derive(Debug, thiserror::Error)]
pub enum PayloadError {
    /// Java casts the tree to an `ObjectNode` and fails on anything else; a message is always an object, because the
    /// id has to go into it.
    #[error("an outbox payload is a JSON object, not {0}")]
    NotAnObject(&'static str),
    #[error("the payload does not serialise: {0}")]
    Unserialisable(#[from] serde_json::Error),
}

/// The text stored in `payload`: the caller's object with `message_id` set to `id`, written as Jackson writes a tree.
pub fn stamped<T: Serialize + ?Sized>(payload: &T, id: Uuid) -> Result<String, PayloadError> {
    let mut members: Map<String, Value> = match serde_json::to_value(payload)? {
        Value::Object(members) => members,
        Value::Null => return Err(PayloadError::NotAnObject("null")),
        Value::Bool(_) => return Err(PayloadError::NotAnObject("a boolean")),
        Value::Number(_) => return Err(PayloadError::NotAnObject("a number")),
        Value::String(_) => return Err(PayloadError::NotAnObject("a string")),
        Value::Array(_) => return Err(PayloadError::NotAnObject("an array")),
    };
    members.insert("message_id".to_owned(), Value::String(id.to_string()));
    write(&members)
}

/// `serde_json`'s compact form with Jackson's one difference: a control character is escaped in **upper-case** hex
/// (`\u001F`, where `serde_json` writes `\u001f`). Nothing else is escaped — not `/`, not DEL, not U+2028 — which
/// `reference/outbox/relay.json`'s stamped rows pin. (`crates/protocol`'s `server::write` is the same writer; the
/// outbox does not depend on the agent's protocol crate for twelve lines.)
fn write(value: &Map<String, Value>) -> Result<String, PayloadError> {
    let mut out = Vec::with_capacity(256);
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, JacksonEscapes);
    value.serialize(&mut serializer)?;
    // Only `str` content reaches the writer, and the formatter adds ASCII to it.
    String::from_utf8(out).map_err(|error| PayloadError::Unserialisable(serde::ser::Error::custom(error.to_string())))
}

struct JacksonEscapes;

impl Formatter for JacksonEscapes {
    fn write_char_escape<W: ?Sized + io::Write>(&mut self, writer: &mut W, escape: CharEscape) -> io::Result<()> {
        let short: &[u8] = match escape {
            CharEscape::Quote => b"\\\"",
            CharEscape::ReverseSolidus => b"\\\\",
            CharEscape::Solidus => b"\\/",
            CharEscape::Backspace => b"\\b",
            CharEscape::FormFeed => b"\\f",
            CharEscape::LineFeed => b"\\n",
            CharEscape::CarriageReturn => b"\\r",
            CharEscape::Tab => b"\\t",
            CharEscape::AsciiControl(byte) => return write!(writer, "\\u{byte:04X}"),
        };
        writer.write_all(short)
    }
}
