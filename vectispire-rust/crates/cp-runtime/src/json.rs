//! JSON text as Jackson writes it — for the few documents whose bytes are read by something that
//! compares them: the audit mirror (a log collector ships it, and the table is checked against it) and
//! the actuator's answers.
//!
//! What differs from `serde_json`'s output, and why it is written here: control characters are
//! `\u00XX` with **upper-case** hex (`serde_json` writes lower-case), `\b` and `\f` are spelled as
//! such, and **key order is the order the document is written in** — `serde_json` without
//! `preserve_order` sorts keys, and Spring's actuator answers `name` first.

use std::fmt::Write;

/// `s` as a JSON string, quotes included.
pub fn string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `Some(s)` as a JSON string, `None` as `null` — Jackson's default for an absent value.
pub fn nullable(s: Option<&str>) -> String {
    s.map_or_else(|| "null".to_owned(), string)
}

/// A `double` as Jackson writes it: `3.0`, never `3`.
pub fn double(value: f64) -> String {
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{value:.1}")
    } else if value.is_finite() {
        format!("{value}")
    } else {
        "null".to_owned()
    }
}

/// An object from already-encoded values, in the order given.
pub fn object(members: &[(&str, String)]) -> String {
    let body: Vec<String> = members.iter().map(|(key, value)| format!("{}:{value}", string(key))).collect();
    format!("{{{}}}", body.join(","))
}

/// An array from already-encoded values.
pub fn array(items: &[String]) -> String {
    format!("[{}]", items.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_are_escaped_with_upper_case_hex() {
        assert_eq!(string("a\u{1f}\u{1}\u{7f}é\u{2028}"), "\"a\\u001F\\u0001\u{7f}é\u{2028}\"");
        assert_eq!(string("\"\\\n\r\t\u{8}\u{c}"), "\"\\\"\\\\\\n\\r\\t\\b\\f\"");
    }

    #[test]
    fn a_double_keeps_its_fraction() {
        assert_eq!(double(3.0), "3.0");
        assert_eq!(double(0.25), "0.25");
        assert_eq!(double(f64::NAN), "null");
    }

    #[test]
    fn an_object_keeps_the_order_it_was_written_in() {
        assert_eq!(object(&[("name", string("x")), ("a", "1".to_owned())]), "{\"name\":\"x\",\"a\":1}");
    }
}
