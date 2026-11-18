//! `ForgePath`: one segment of a forge API path, built from a value the forge or a person supplied. **Every adapter
//! builds its URLs through this**: a `/` would add a segment, a `?` or `#` end the path, a `%` be decoded by the
//! server. Everything but RFC 3986's unreserved characters is percent-encoded, the slash included; a segment that is
//! only dots — or empty — is refused, since a server or a proxy removes or decodes it into a dot segment.

/// `value` as one path segment, or `None` when no segment can carry it.
pub(crate) fn segment(value: Option<&str>) -> Option<String> {
    let value = value?;
    if value.is_empty() || value.chars().all(|c| c == '.') {
        return None;
    }
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len().saturating_add(8));
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            for nibble in [byte >> 4, byte & 0xF] {
                encoded.push(HEX.get(usize::from(nibble)).map_or('0', |digit| char::from(*digit)));
            }
        }
    }
    Some(encoded)
}

/// `UUID.fromString`: the canonical form, or Java's lenient one of five hexadecimal groups of at most 8, 4, 4, 4 and
/// 12 digits — answered in the canonical lower case the columns store.
pub(crate) fn java_uuid(text: &str) -> Option<String> {
    if text.is_empty() || text.len() > 36 {
        return None;
    }
    let groups: Vec<&str> = text.split('-').collect();
    let widths = [8usize, 4, 4, 4, 12];
    if groups.len() != 5 {
        return None;
    }
    let mut canonical = Vec::with_capacity(5);
    for (group, width) in groups.iter().zip(widths) {
        if group.is_empty() || group.len() > width || !group.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        canonical.push(format!("{:0>width$}", group.to_ascii_lowercase()));
    }
    Some(canonical.join("-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_but_the_unreserved_is_encoded() {
        assert_eq!(segment(Some("group/sub project")).as_deref(), Some("group%2Fsub%20project"));
        assert_eq!(segment(Some("a+b*c~d.e_f-g")).as_deref(), Some("a%2Bb%2Ac~d.e_f-g"));
        assert_eq!(segment(Some("é?#%")).as_deref(), Some("%C3%A9%3F%23%25"));
        assert_eq!(segment(Some("v1.2..3")).as_deref(), Some("v1.2..3"));
    }

    #[test]
    fn uuids_read_as_java_reads_them() {
        assert_eq!(
            java_uuid("11111111-2222-3333-4444-555555555555").as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
        assert_eq!(java_uuid("1-2-3-4-5").as_deref(), Some("00000001-0002-0003-0004-000000000005"));
        assert_eq!(
            java_uuid("ABCDEF01-2222-3333-4444-555555555555").as_deref(),
            Some("abcdef01-2222-3333-4444-555555555555")
        );
        assert_eq!(java_uuid("not-a-uuid"), None);
        assert_eq!(java_uuid("1-2-3-4"), None);
    }

    #[test]
    fn dots_alone_and_nothing_are_refused() {
        for refused in [Some(""), Some("."), Some(".."), Some("..."), None] {
            assert_eq!(segment(refused), None, "{refused:?}");
        }
    }
}
