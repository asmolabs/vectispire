//! JSON as the Java side's Jackson writes it, for everything the port sends that a Java reader — or a person
//! comparing bytes with Java's — would read: the agent's results, the control plane's problem documents and
//! audit mirror, the contract's recorded answers.
//!
//! Two differences from `serde_json`'s compact writer, both found by the reference sets: a control character is
//! escaped with **upper-case** hex (`\u001F`, where serde writes `\u001f`), and a double is written by
//! `Double.toString` (`1.0E10`, where serde writes `10000000000.0`). Object keys keep the order the value holds —
//! document order, since the workspace turns on `serde_json`'s `preserve_order` — so a forwarded document is
//! byte-faithful as well as a struct. One implementation, here, because four copies of an escaping table drift.

/// A JSON string the way Jackson's default writer spells it: `"` and `\` escaped, the short escapes for the
/// five control characters that have one, `\u00XX` with **upper-case** hex for the rest below 0x20, everything
/// else — non-ASCII included — as it is.
pub fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
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

/// JSON as Jackson writes it — the wire form a finding, a problem document or an audit line travels in.
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

    #[test]
    fn strings_are_escaped_as_jackson_escapes_them() {
        let mut out = String::new();
        write_string(&mut out, "a\"b\\c\n\u{1f}\u{7f}é");
        assert_eq!(out, "\"a\\\"b\\\\c\\n\\u001F\u{7f}é\"");
    }

    #[test]
    fn a_value_is_written_with_the_same_escaping_and_in_document_order() {
        let value = serde_json::json!({ "b": "x\u{1f}", "a": [1, 2.5, null, true] });
        assert_eq!(to_wire_string(&value), r#"{"b":"x\u001F","a":[1,2.5,null,true]}"#);
    }
}
