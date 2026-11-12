//! The string rules an entry's fields pass through before they are stored — Java's, because the stored text is
//! what the hash covers.

/// The width of the bounded text columns of `t_audit_log`.
pub const TEXT_COLUMN: usize = 255;
/// The width of `ip_address`.
pub const ADDRESS_COLUMN: usize = 64;

/// `AuditLogService.truncate`: at most `width` UTF-16 code units, as `String.length` counts, and never half a
/// surrogate pair — a lone high surrogate is not UTF-8, and an engine may refuse the row for it, the failure the
/// cut exists to prevent. Keeping whole characters while they fit is exactly Java's cut at `width`, or at
/// `width - 1` when that unit is a high surrogate.
pub fn truncate(value: &str, width: usize) -> &str {
    let mut units = 0;
    for (index, c) in value.char_indices() {
        units = usize::saturating_add(units, c.len_utf16());
        if units > width {
            return value.get(..index).unwrap_or(value);
        }
    }
    value
}

/// [`truncate`] of an optional value.
pub fn truncate_optional(value: Option<&str>, width: usize) -> Option<String> {
    value.map(|value| truncate(value, width).to_owned())
}

/// `Character.isWhitespace`, which `String.isBlank` asks: the Unicode space separators except the three
/// non-breaking ones, and the controls `\t`, `\n`, `\u000B`, `\f`, `\r` and `\u001C`–`\u001F`.
pub fn is_java_whitespace(c: char) -> bool {
    let space_separator = matches!(
        c,
        '\u{20}' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
    );
    matches!(c, '\u{9}'..='\u{d}' | '\u{1c}'..='\u{1f}')
        || (space_separator && !matches!(c, '\u{a0}' | '\u{2007}' | '\u{202f}'))
}

/// `String.isBlank`.
pub fn is_blank(value: &str) -> bool {
    value.chars().all(is_java_whitespace)
}

/// `AuditLogService.blankToNull`.
pub fn blank_to_none(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !is_blank(value))
}

/// `String.trim`: every leading and trailing character up to U+0020, which is not `char::trim`'s Unicode white
/// space.
pub fn java_trim(value: &str) -> &str {
    value.trim_matches(|c: char| c <= ' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cut_counts_utf16_units_and_never_splits_a_pair() {
        assert_eq!(truncate("abcdef", 4), "abcd");
        assert_eq!(truncate("abc🛡", 4), "abc", "the pair would straddle the width");
        assert_eq!(truncate("ab🛡", 4), "ab🛡", "the pair fits exactly");
        assert_eq!(truncate("éé", 1), "é", "a BMP character is one unit, whatever its UTF-8 length");
        assert_eq!(truncate("short", 255), "short");
    }

    #[test]
    fn blank_is_java_whitespace_only() {
        assert!(is_blank(""));
        assert!(is_blank(" \t\n\u{1f}\u{2003}"));
        assert!(!is_blank("\u{a0}"), "a non-breaking space is not white space to Java");
        assert!(!is_blank("x"));
    }
}
