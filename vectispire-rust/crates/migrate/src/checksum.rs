//! The checksum Flyway 12.4 records for a versioned SQL migration.
//!
//! **A port of `ChecksumCalculator.calculateChecksumForResource`, nothing more.** Flyway reads the
//! script through a `BufferedReader`, removes a byte-order mark from the first line, and feeds the
//! UTF-8 bytes of every line, its terminator dropped, to one `java.util.zip.CRC32`; the column holds
//! that value cast to a Java `int`. It is computed over the file **as stored**, before placeholders
//! are replaced (`SqlMigrationResolver.getChecksumForLoadableResource` replaces them for repeatable
//! migrations only), which is why a value of `MigrationDialect` can change without a checksum moving.
//!
//! Two consequences a reader would not guess, both pinned by the tests below:
//!
//! - **Line endings do not count.** `readLine` ends a line at `\n`, `\r` or `\r\n`, so a file
//!   checked out with CRLF has the checksum of the same file with LF. A blank line adds nothing.
//! - **Only the first byte-order mark is removed.** A second one, or one at the start of a later line,
//!   is content.
//!
//! What the Java code checks in `reference/checksums-*.tsv` was written by the real Flyway into a real
//! database; `tests/checksums.rs` recomputes every one of them.

use crate::Error;

/// Flyway's checksum of a migration's bytes, as the `checksum` column stores it.
///
/// Refuses a file that is not UTF-8. Flyway decodes with a replacing decoder and would checksum the
/// replacement characters; no migration of this project is anything but UTF-8, and a file that is not
/// has been damaged — refusing says so instead of recording a checksum of the damage.
pub fn of(script: &str, bytes: &[u8]) -> Result<i32, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::NotUtf8 { script: script.to_owned() })?;
    Ok(of_text(text))
}

/// The checksum of text already decoded.
pub fn of_text(text: &str) -> i32 {
    let mut crc = crc32fast::Hasher::new();
    let mut first = true;
    for line in lines(text) {
        let line = if first { line.strip_prefix('\u{feff}').unwrap_or(line) } else { line };
        first = false;
        crc.update(line.as_bytes());
    }
    // `(int) crc32.getValue()`: the low 32 bits, reinterpreted as signed.
    i32::from_ne_bytes(crc.finalize().to_ne_bytes())
}

/// The lines `BufferedReader.readLine` returns: split at `\n`, `\r` or `\r\n`, terminators dropped,
/// and no empty last line after a final terminator.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    let bytes = text.as_bytes();
    let mut start = 0;
    let mut position = 0;
    std::iter::from_fn(move || {
        if start >= bytes.len() {
            return None;
        }
        while position < bytes.len() {
            match bytes[position] {
                b'\n' => {
                    let line = &text[start..position];
                    position += 1;
                    start = position;
                    return Some(line);
                }
                b'\r' => {
                    let line = &text[start..position];
                    position += 1;
                    if bytes.get(position) == Some(&b'\n') {
                        position += 1;
                    }
                    start = position;
                    return Some(line);
                }
                _ => position += 1,
            }
        }
        let line = &text[start..];
        start = bytes.len();
        Some(line)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn java_crc(lines: &[&str]) -> i32 {
        let mut crc = crc32fast::Hasher::new();
        for line in lines {
            crc.update(line.as_bytes());
        }
        i32::from_ne_bytes(crc.finalize().to_ne_bytes())
    }

    #[test]
    fn the_terminators_are_dropped_whatever_they_are() {
        let expected = java_crc(&["create table a (id int);", "", "insert into a values (1);"]);
        assert_eq!(of_text("create table a (id int);\n\ninsert into a values (1);\n"), expected);
        assert_eq!(of_text("create table a (id int);\r\n\r\ninsert into a values (1);\r\n"), expected);
        assert_eq!(of_text("create table a (id int);\r\rinsert into a values (1);"), expected);
    }

    #[test]
    fn a_leading_byte_order_mark_is_removed_and_no_other() {
        assert_eq!(of_text("\u{feff}select 1;"), of_text("select 1;"));
        assert_ne!(of_text("select 1;\n\u{feff}select 2;"), of_text("select 1;\nselect 2;"));
        assert_ne!(of_text("\u{feff}\u{feff}select 1;"), of_text("select 1;"));
    }

    #[test]
    fn an_empty_file_has_the_checksum_of_nothing() {
        assert_eq!(of_text(""), 0);
        assert_eq!(of_text("\n\n"), 0);
    }

    #[test]
    fn the_value_is_signed_as_a_java_int() {
        // CRC32("a") = 0xe8b7be43, which a Java `int` holds as a negative number.
        assert_eq!(of_text("a"), -390_611_389);
        assert_eq!(of_text("a"), 0xe8b7_be43_u32 as i32);
    }

    #[test]
    fn a_file_that_is_not_utf8_is_refused() {
        assert!(matches!(of("V1__x.sql", &[0x66, 0xff, 0x0a]), Err(Error::NotUtf8 { .. })));
    }
}
