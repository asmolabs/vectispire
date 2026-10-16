//! How Jackson's tree model reads JSON, for the parsers that must read it the same way.
//!
//! The Java parsers read scanner output with `ObjectMapper.readTree` and the lenient accessors
//! `path(…).asText(default)` and `asInt(default)`. Those decide what a finding says when a scanner
//! writes a number where text was expected, or text where a number was — and the finding's fields
//! are fingerprint material. Each rule below is pinned by `reference/secrets/`.

use serde::Deserialize;
use serde_json::Value;

/// `ObjectMapper.readTree(String)`: the first JSON value of the text, **trailing content ignored**
/// as Jackson ignores it; `None` where Jackson would throw.
///
/// A byte-order mark is not white space to Jackson's string reader, so a report that starts with one
/// does not parse — as on the Java side.
pub fn read_tree(content: &str) -> Option<Value> {
    let mut deserializer = serde_json::Deserializer::from_str(content);
    Value::deserialize(&mut deserializer).ok()
}

/// `ObjectMapper.reader().with(FAIL_ON_TRAILING_TOKENS).readTree(String)`: the one JSON value the text
/// holds, `None` for anything after it, for a blank text, or where Jackson would throw.
///
/// The reading gitleaks' report is held to: a report followed by anything else is not what the tool
/// wrote — two runs' output concatenated, or a stream spliced.
pub fn read_tree_strict(content: &str) -> Option<Value> {
    serde_json::from_str(content).ok()
}

/// `node.path(field)`: the member of an object, absent for anything else.
pub fn path<'a>(node: &'a Value, field: &str) -> Option<&'a Value> {
    node.as_object().and_then(|object| object.get(field))
}

/// `asText(default)`: a scalar's text; the default for null or absent; `""` for an object or an
/// array, whatever the default — a container's `asText()` is empty, and the default is only taken
/// for a missing or null value.
pub fn as_text(node: Option<&Value>, default: &str) -> String {
    match node {
        None | Some(Value::Null) => default.to_owned(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Bool(flag)) => flag.to_string(),
        Some(Value::Number(number)) => number_text(number),
        Some(Value::Array(_) | Value::Object(_)) => String::new(),
    }
}

/// `asInt(default)`, as `IntNode`, `LongNode`, `DoubleNode`, `TextNode` and `BooleanNode` each do it.
pub fn as_int(node: Option<&Value>, default: i32) -> i32 {
    match node {
        Some(Value::Number(number)) => {
            if let Some(integer) = number.as_i64() {
                // `LongNode.asInt` is a cast: it keeps the low 32 bits.
                integer as i32
            } else if let Some(unsigned) = number.as_u64() {
                // Beyond a long, Jackson holds a BigInteger and `intValue` keeps the low 32 bits too.
                unsigned as u32 as i32
            } else {
                // `(int) double`: truncation, saturating, NaN as zero — what `as` does.
                number.as_f64().map_or(default, |float| float as i32)
            }
        }
        Some(Value::String(text)) => parse_as_int(text, default),
        Some(Value::Bool(flag)) => i32::from(*flag),
        _ => default,
    }
}

/// `NumberInput.parseAsInt`: trimmed, a sign, digits as an int — and anything else through
/// `Double.parseDouble`, cast.
fn parse_as_int(text: &str, default: i32) -> i32 {
    let trimmed = java_trim(text);
    if trimmed.is_empty() {
        return default;
    }
    let unsigned = trimmed.strip_prefix('+').unwrap_or(trimmed);
    let digits = unsigned.strip_prefix('-').unwrap_or(unsigned);
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return java_parse_double(unsigned).map_or(default, |value| value as i32);
    }
    unsigned.parse::<i32>().unwrap_or(default)
}

/// `Character.isWhitespace`, which `String.strip` asks: not the no-break spaces, unlike Rust's.
pub fn is_java_whitespace(c: char) -> bool {
    matches!(c, '\u{9}'..='\u{d}' | '\u{1c}'..='\u{20}' | '\u{1680}' | '\u{2000}'..='\u{2006}' | '\u{2008}'..='\u{200a}'
        | '\u{2028}' | '\u{2029}' | '\u{205f}' | '\u{3000}')
}

/// `String.trim`: every char up to U+0020 at both ends.
fn java_trim(text: &str) -> &str {
    text.trim_matches(|c: char| c <= ' ')
}

/// `Double.parseDouble`, for the forms a scanner writes: decimal and exponent notation, `Infinity`
/// and `NaN`, an optional sign and a trailing type letter. Hexadecimal floating point is refused —
/// Java reads it, but no scanner writes it, and refusing it gives Jackson's default either way for
/// the `0x…` integers that do occur.
fn java_parse_double(text: &str) -> Option<f64> {
    let trimmed = java_trim(text);
    let unsigned = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
    let negative = trimmed.starts_with('-');
    let value = match unsigned {
        "Infinity" => f64::INFINITY,
        "NaN" => f64::NAN,
        _ => {
            let body = unsigned.strip_suffix(['d', 'D', 'f', 'F']).unwrap_or(unsigned);
            let valid = !body.is_empty()
                && body.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'))
                && body.bytes().any(|b| b.is_ascii_digit());
            if !valid {
                return None;
            }
            body.parse::<f64>().ok()?
        }
    };
    Some(if negative { -value } else { value })
}

/// A number's text as Jackson's `asText` writes it: an integer's digits, a double through
/// `Double.toString`.
fn number_text(number: &serde_json::Number) -> String {
    if number.is_i64() || number.is_u64() {
        return number.to_string();
    }
    number.as_f64().map_or_else(|| number.to_string(), java_double_to_string)
}

/// `Double.toString`: plain notation for `10⁻³ ≤ |d| < 10⁷`, with at least one fraction digit, and
/// `d.dddE±n` otherwise — the shortest digits that read back as the same double, in both.
pub fn java_double_to_string(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity".to_owned() } else { "-Infinity".to_owned() };
    }
    if value == 0.0 {
        return if value.is_sign_negative() { "-0.0".to_owned() } else { "0.0".to_owned() };
    }
    let magnitude = value.abs();
    if (1e-3..1e7).contains(&magnitude) {
        let plain = format!("{value}");
        return if plain.contains('.') { plain } else { format!("{plain}.0") };
    }
    // `{:e}` gives the shortest digits as `1.5e10` or `1e-5`.
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((scientific.as_str(), "0"));
    let mantissa = if mantissa.contains('.') { mantissa.to_owned() } else { format!("{mantissa}.0") };
    format!("{mantissa}E{exponent}")
}

/// JSON as the agent's Jackson mapper writes it — the wire form a finding travels in.
///
/// Two differences from `serde_json`'s compact writer, both found by `reference/dependencies/`: a
/// control character is escaped with **upper-case** hex (`\u001F`, where serde writes `\u001f`), and a
/// double is written by `Double.toString` (`1.0E10`, where serde writes `10000000000.0`). Object keys
/// keep the order the value holds — document order, since the workspace turns on `serde_json`'s
/// `preserve_order` — so a forwarded document is byte-faithful as well as a struct.
pub fn to_wire_string<T: serde::Serialize + ?Sized>(value: &T) -> String {
    let mut out = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, WireFormatter);
    // A `Serialize` of plain data into memory does not fail; an `Err` here is a type that refuses itself.
    if value.serialize(&mut serializer).is_err() {
        return String::new();
    }
    String::from_utf8(out).unwrap_or_default()
}

struct WireFormatter;

impl serde_json::ser::Formatter for WireFormatter {
    fn write_char_escape<W: ?Sized + std::io::Write>(
        &mut self,
        writer: &mut W,
        char_escape: serde_json::ser::CharEscape,
    ) -> std::io::Result<()> {
        use serde_json::ser::CharEscape;
        let short = match char_escape {
            CharEscape::Quote => b'"',
            CharEscape::ReverseSolidus => b'\\',
            CharEscape::Solidus => b'/',
            CharEscape::Backspace => b'b',
            CharEscape::FormFeed => b'f',
            CharEscape::LineFeed => b'n',
            CharEscape::CarriageReturn => b'r',
            CharEscape::Tab => b't',
            CharEscape::AsciiControl(byte) => return write!(writer, "\\u{byte:04X}"),
        };
        writer.write_all(&[b'\\', short])
    }

    fn write_f64<W: ?Sized + std::io::Write>(&mut self, writer: &mut W, value: f64) -> std::io::Result<()> {
        writer.write_all(java_double_to_string(value).as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubles_read_as_java_writes_them() {
        for (value, text) in [
            (1e10, "1.0E10"),
            (0.001, "0.001"),
            (1e-5, "1.0E-5"),
            (12345678.9, "1.23456789E7"),
            (100.0, "100.0"),
            (-0.0, "-0.0"),
        ] {
            assert_eq!(java_double_to_string(value), text);
        }
    }
}
