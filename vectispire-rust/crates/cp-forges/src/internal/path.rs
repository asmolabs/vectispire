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
    let mut encoded = String::with_capacity(value.len() + 8);
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0xF)]));
        }
    }
    Some(encoded)
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
    fn dots_alone_and_nothing_are_refused() {
        for refused in [Some(""), Some("."), Some(".."), Some("..."), None] {
            assert_eq!(segment(refused), None, "{refused:?}");
        }
    }
}
