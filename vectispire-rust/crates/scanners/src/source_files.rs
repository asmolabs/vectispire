//! Reading a file of the repository under analysis, in the agent's own process — `SourceFiles`.
//!
//! **The content is the author's, and so is its shape.** The scanners in containers are bounded by the
//! container; the manifest reader and the API discovery run here. On the Java side a committed
//! `a.js -> /dev/zero` never reached end of file and took the embedded worker down, a `package.json -> /etc/…`
//! read a host file into the recorded version, and a 1 GB source file did the first without the link. So a file
//! is read only if it is a regular file *itself* — not through a link — and only up to [`MAX_BYTES`], a bound
//! enforced while reading too, since a file can grow between the check and the read.

use std::fs::{File, Metadata};
use std::io::Read;
use std::path::Path;

/// Larger than any manifest or source file worth parsing; smaller than any heap — `SourceFiles.MAX_BYTES`.
pub const MAX_BYTES: u64 = 2 * 1024 * 1024;

/// A regular file, not reached through a symbolic link.
pub fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

/// Whether a walk should read this entry at all — the walk's metadata does not follow links.
pub fn is_readable(metadata: &Metadata) -> bool {
    metadata.file_type().is_file() && metadata.len() <= MAX_BYTES
}

/// The file's bytes, `None` when it is absent, a link, not a regular file, or too large; an error when a
/// regular file of acceptable size cannot be read.
pub fn read_bytes(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !is_readable(&metadata) {
        return Ok(None);
    }
    // `O_NOFOLLOW` on the open as well: the entry checked above could have been replaced by a link since. And
    // `O_NONBLOCK`, which Java does not ask for: an entry replaced by a FIFO in that same moment would otherwise
    // hold the open until somebody writes to it — a regular file reads the same either way.
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let mut bytes = Vec::new();
    File::from(descriptor).take(MAX_BYTES.saturating_add(1)).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_or(true, |read| read > MAX_BYTES) {
        return Ok(None);
    }
    Ok(Some(bytes))
}

/// The file as text, decoded as `new String(bytes, UTF_8)` decodes — see [`java_utf8`].
pub fn read_text(path: &Path) -> std::io::Result<Option<String>> {
    Ok(read_bytes(path)?.map(|bytes| java_utf8(&bytes)))
}

/// `new String(bytes, UTF_8)`: each malformed sequence one U+FFFD, as the JDK's decoder delimits them.
///
/// Rust's `from_utf8_lossy` delimits them as the WHATWG does, and agrees with the JDK everywhere but on an encoded
/// surrogate — `ED A0 80` — which the JDK decodes whole and replaces once, where the WHATWG replaces each of its
/// three bytes. A path or a summary written with one is fingerprint material for the inventory.
pub fn java_utf8(bytes: &[u8]) -> String {
    let continuation = |byte: Option<&u8>| byte.is_some_and(|&byte| byte & 0xC0 == 0x80);
    let mut text = String::with_capacity(bytes.len());
    let mut at = 0usize;
    while let Some(&lead) = bytes.get(at) {
        let next = |offset: usize| bytes.get(at.saturating_add(offset));
        let (decoded, consumed) = match lead {
            0x00..=0x7F => (Some(char::from(lead)), 1),
            0xC2..=0xDF => match next(1) {
                Some(&second) if continuation(Some(&second)) => {
                    (char::from_u32(u32::from(lead & 0x1F) << 6 | u32::from(second & 0x3F)), 2)
                }
                _ => (None, 1),
            },
            0xE0..=0xEF => {
                let overlong =
                    |second: Option<&u8>| lead == 0xE0 && second.is_some_and(|&second| second & 0xE0 == 0x80);
                match (next(1), next(2)) {
                    (Some(_), Some(_)) if overlong(next(1)) || !continuation(next(1)) => (None, 1),
                    (Some(_), Some(_)) if !continuation(next(2)) => (None, 2),
                    (Some(&second), Some(&third)) => {
                        let value =
                            u32::from(lead & 0x0F) << 12 | u32::from(second & 0x3F) << 6 | u32::from(third & 0x3F);
                        // A surrogate is decoded whole, then replaced: one U+FFFD for the three bytes.
                        (Some(char::from_u32(value).unwrap_or('\u{FFFD}')), 3)
                    }
                    // Cut by the end of the input: one replacement for what is left of a well-begun sequence.
                    (Some(_), None) if overlong(next(1)) || !continuation(next(1)) => (None, 1),
                    (Some(_), None) => (None, 2),
                    (None, _) => (None, 1),
                }
            }
            0xF0..=0xF4 => {
                let second_ok = |second: u8| match lead {
                    0xF0 => (0x90..=0xBF).contains(&second),
                    0xF4 => second & 0xF0 == 0x80,
                    _ => second & 0xC0 == 0x80,
                };
                match (next(1), next(2), next(3)) {
                    (Some(&second), Some(&third), Some(&fourth))
                        if second_ok(second) && continuation(Some(&third)) && continuation(Some(&fourth)) =>
                    {
                        let value = u32::from(lead & 0x07) << 18
                            | u32::from(second & 0x3F) << 12
                            | u32::from(third & 0x3F) << 6
                            | u32::from(fourth & 0x3F);
                        (char::from_u32(value), 4)
                    }
                    (Some(&second), third, _) if second_ok(second) => (None, if continuation(third) { 3 } else { 2 }),
                    _ => (None, 1),
                }
            }
            _ => (None, 1),
        };
        text.push(decoded.unwrap_or('\u{FFFD}'));
        at = at.saturating_add(consumed);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_a_directory_and_an_oversized_file_are_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "host").unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret"), dir.path().join("link")).unwrap();
        std::fs::write(dir.path().join("big"), vec![b'x'; usize::try_from(MAX_BYTES).unwrap() + 1]).unwrap();
        std::fs::write(dir.path().join("limit"), vec![b'x'; usize::try_from(MAX_BYTES).unwrap()]).unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();

        assert_eq!(read_bytes(&dir.path().join("link")).unwrap(), None);
        assert!(!is_regular_file(&dir.path().join("link")));
        assert_eq!(read_bytes(&dir.path().join("big")).unwrap(), None);
        assert_eq!(read_bytes(&dir.path().join("sub")).unwrap(), None);
        assert_eq!(read_bytes(&dir.path().join("missing")).unwrap(), None);
        assert_eq!(read_bytes(&dir.path().join("limit")).unwrap().map(|bytes| bytes.len()), Some(2 * 1024 * 1024));
        assert_eq!(read_text(&dir.path().join("limit")).unwrap().map(|text| text.len()), Some(2 * 1024 * 1024));
    }

    #[test]
    fn invalid_utf8_is_replaced_as_java_replaces_it() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), b"x\xe2\x82y\xff").unwrap();
        assert_eq!(read_text(&dir.path().join("a")).unwrap().as_deref(), Some("x\u{fffd}y\u{fffd}"));
        let replaced = |bytes: &[u8]| java_utf8(bytes).chars().filter(|&c| c == '\u{fffd}').count();
        assert_eq!(replaced(b"\xed\xa0\x80"), 1, "an encoded surrogate is one replacement");
        assert_eq!(replaced(b"\xed\xbf\xbfx"), 1);
        assert_eq!(replaced(b"\xed\xa0"), 1, "cut short too");
        assert_eq!(replaced(b"\xe0\x80\x80"), 3, "an overlong form is three");
        assert_eq!(replaced(b"\xc0\xaf"), 2);
        assert_eq!(replaced(b"\xf4\x90\x80\x80"), 4);
        assert_eq!(replaced(b"\xf0\x80\x80"), 3);
        assert_eq!(replaced(b"\xf0\x90\x80"), 1);
        assert_eq!(replaced(b"\xf0\x90\x80x"), 1);
        assert_eq!(replaced(b"\xf0\x90"), 1);
        assert_eq!(replaced(b"\xe2\x82\""), 1);
        assert_eq!(replaced(b"\xf8\x88\x80\x80\x80"), 5);
        assert_eq!(java_utf8("é😀\u{7ff}\u{ffff}".as_bytes()), "é😀\u{7ff}\u{ffff}");
        // Away from surrogates, the JDK delimits as the WHATWG does.
        for bytes in [&b"\xc2"[..], b"\xe2\x82x\xff", b"\xf5\x80", b"\x80\xbf", b"\xe0\xa0", b"\xf4\x8f\xbf"] {
            assert_eq!(java_utf8(bytes), String::from_utf8_lossy(bytes), "{bytes:?}");
        }
    }
}
