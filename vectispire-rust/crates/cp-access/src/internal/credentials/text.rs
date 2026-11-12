//! The few `java.lang.String` behaviours the credential rules are written in. A port that used Rust's notion of
//! whitespace or length instead would accept a header, a scope or a name the Java control plane refuses, and the
//! other way round.

/// `String.trim()`: strips every leading and trailing character at or below U+0020 — the ASCII controls included,
/// and nothing beyond them (not U+00A0, not U+2003).
pub fn java_trim(text: &str) -> &str {
    text.trim_matches(|c: char| c <= ' ')
}

/// `\s` in a `java.util.regex` pattern without `UNICODE_CHARACTER_CLASS`: `[ \t\n\x0B\f\r]`.
pub fn is_java_regex_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r')
}

/// `Character.isWhitespace`, which `String.isBlank()` reads: the Unicode space separators except the no-break ones,
/// the line and paragraph separators, and the controls U+0009–U+000D and U+001C–U+001F.
pub fn is_java_whitespace(c: char) -> bool {
    match c {
        '\u{00A0}' | '\u{2007}' | '\u{202F}' => false,
        '\u{09}'..='\u{0D}' | '\u{1C}'..='\u{1F}' => true,
        _ => c.is_whitespace() && c != '\u{85}',
    }
}

/// `String.isBlank()`.
pub fn java_is_blank(text: &str) -> bool {
    text.chars().all(is_java_whitespace)
}

/// `String.length()`: UTF-16 code units, which is what a Java length limit counts.
pub fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// `String.split(regex)` for a one-character literal separator: the pieces, with the trailing empty ones removed
/// (and a leading empty one kept), as Java returns them.
pub fn java_split(text: &str, separator: char) -> Vec<&str> {
    let mut pieces: Vec<&str> = text.split(separator).collect();
    while pieces.last().is_some_and(|piece| piece.is_empty()) {
        pieces.pop();
    }
    pieces
}

/// `value.substring(0, limit)` when `value.length() > limit`, counted in UTF-16 code units. A pair that the cut would
/// split is left out whole, where Java would keep a lone high surrogate the database then refuses or mangles.
pub fn clip_utf16(value: &str, limit: usize) -> &str {
    let mut units = 0usize;
    for (index, c) in value.char_indices() {
        let width = c.len_utf16();
        if units.saturating_add(width) > limit {
            return value.get(..index).unwrap_or(value);
        }
        units = units.saturating_add(width);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_is_javas() {
        assert_eq!(java_trim("\u{1}\t a b \u{1F}"), "a b");
        assert_eq!(java_trim("\u{A0}x\u{A0}"), "\u{A0}x\u{A0}");
    }

    #[test]
    fn blank_is_javas() {
        assert!(java_is_blank(""));
        assert!(java_is_blank(" \t\u{1C}\u{2003}"));
        assert!(!java_is_blank("\u{A0}"));
        assert!(!java_is_blank("\u{85}"));
    }

    #[test]
    fn split_drops_trailing_empties_only() {
        assert_eq!(java_split("$a$$b$$", '$'), vec!["", "a", "", "b"]);
        assert_eq!(java_split("", ','), Vec::<&str>::new());
        assert_eq!(java_split(",,", ','), Vec::<&str>::new());
    }

    #[test]
    fn lengths_and_cuts_count_utf16_units() {
        assert_eq!(utf16_len("é😀"), 3);
        assert_eq!(clip_utf16("ab😀c", 3), "ab");
        assert_eq!(clip_utf16("ab😀c", 4), "ab😀");
        assert_eq!(clip_utf16("abc", 255), "abc");
    }
}
