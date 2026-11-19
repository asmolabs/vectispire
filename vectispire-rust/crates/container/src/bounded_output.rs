//! A directory a tool may write into which **cannot hold more than its ceiling** — `ContainerRun.BoundedOutput`,
//! with what is read back from it (`ContainerRunner.CollectedOutput`, `OutputFile`) and how (`OutputArchive`).
//!
//! **A bind mount carries no size**: a plugin — code somebody else wrote — could fill the executor's disk through
//! one for as long as its timeout allowed. A size-limited tmpfs is the bound the kernel enforces, and the archive
//! API cannot read a container's own `HostConfig.Tmpfs`; it can read a *volume*. So the directory is an anonymous
//! volume of the local driver, of type tmpfs with `size=` and `nr_inodes=`, declared inside the create call (the
//! socket proxy's `VOLUMES: 0` stays as it is), kept mounted by a **holder** — a pinned busybox that only sleeps,
//! in the same closed shape — and reached by the tool through `VolumesFrom`. The file is read from the holder once
//! the tool has exited, then the holder is stopped and prints what the kernel says of the directory (`df`), the
//! one measurement of "full" that does not guess. Memory, not disk: the pages are charged to the tool's ceiling.
//!
//! The run itself is [`crate::ContainerRunner::run_with`]; the shapes it sends the daemon are held to what the Java
//! runner sends by `reference/plugins/creates/`, and the archive and `df` readings to `reference/plugins/archives/`
//! and `measurements/`.

use vectispire_domain::java;

/// The files a bounded output holds by default — `ContainerRunner.OUTPUT_INODES`: a report and what a tool leaves
/// beside it. Each inode is kernel memory no size limit counts.
pub const OUTPUT_INODES: u32 = 4096;

/// A writable directory with a ceiling, read back by the runner — `ContainerRun.BoundedOutput`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedOutput {
    /// Where the directory appears in the container.
    pub target: String,
    /// What it may hold, everything in it counted.
    pub bytes: u64,
    /// The image that keeps the directory alive, pinned by digest like any other.
    pub holder_image: String,
    /// The one file read back — a bare name in `target`.
    pub file: String,
    /// The files and directories it may hold, itself included.
    pub inodes: u32,
}

/// Why a bounded output was refused before anything ran — the record's own checks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidBoundedOutput(pub &'static str);

impl BoundedOutput {
    /// A directory's worth of files ([`OUTPUT_INODES`]).
    pub fn new(
        target: impl Into<String>,
        bytes: u64,
        holder_image: impl Into<String>,
        file: impl Into<String>,
    ) -> Result<BoundedOutput, InvalidBoundedOutput> {
        BoundedOutput::with_inodes(target, bytes, holder_image, file, OUTPUT_INODES)
    }

    pub fn with_inodes(
        target: impl Into<String>,
        bytes: u64,
        holder_image: impl Into<String>,
        file: impl Into<String>,
        inodes: u32,
    ) -> Result<BoundedOutput, InvalidBoundedOutput> {
        let file = file.into();
        if bytes == 0 {
            return Err(InvalidBoundedOutput("A bounded output holds a positive number of bytes."));
        }
        if file.is_empty() || file.contains('/') || file.starts_with('.') {
            return Err(InvalidBoundedOutput("The file read back is a bare name in the output directory."));
        }
        if inodes < 2 {
            // The directory is one, the file another: fewer and nothing could ever be written.
            return Err(InvalidBoundedOutput("A bounded output holds at least its directory and one file."));
        }
        Ok(BoundedOutput { target: target.into(), bytes, holder_image: holder_image.into(), file, inodes })
    }
}

/// The one file read back from a bounded output, as the archive answered it — `ContainerRunner.OutputFile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputFile {
    /// The tool wrote no file of that name.
    Missing,
    /// A link, a directory, a FIFO — anything but a regular file of that name; not read.
    NotRegular,
    /// Larger than the ceiling; not read.
    TooLarge(u64),
    /// The file's bytes, within the ceiling.
    Read(Vec<u8>),
}

/// What a bounded output held when its tool exited, in the kernel's words — `ContainerRunner.CollectedOutput`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedOutput {
    /// What it could hold, in bytes.
    pub capacity: u64,
    /// What was left, as `df` answered it — a Java `long`, its KiB multiplied as Java multiplies them (wrapping: a
    /// value no tmpfs of a bounded size can print, read as full).
    pub available_bytes: i64,
    /// The files it could still have created.
    pub available_inodes: i64,
    pub file: OutputFile,
}

impl CollectedOutput {
    /// Less than one page left, or no inode: a write was refused, or the next one would have been.
    pub fn full(&self) -> bool {
        self.available_bytes < 4096 || self.available_inodes <= 0
    }

    /// The holder's `df -P -k` and `df -P -i` lines for the directory, or `None` when either is missing — a holder
    /// that died printed nothing, and a guess would be believed.
    pub fn measured(bounded: &BoundedOutput, printed: &str, file: OutputFile) -> Option<CollectedOutput> {
        // `Filesystem Size Used Available Capacity Mounted-on`: the fourth column of the two lines naming the
        // directory — the first in KiB, the second in inodes.
        let suffix = format!(" {}", bounded.target);
        let available: Vec<i64> = java_lines(printed)
            .map(java::strip)
            .filter(|line| line.ends_with(&suffix))
            .filter_map(|line| {
                let columns: Vec<&str> = split_whitespace_java(line);
                match columns.as_slice() {
                    [_, _, _, available, _, _]
                        if !available.is_empty() && available.chars().count() < 19 && available.chars().all(|c| java::digit(c).is_some()) =>
                    {
                        parse_signed(available, 10)
                    }
                    _ => None,
                }
            })
            .collect();
        let [kib, inodes] = available.as_slice() else { return None };
        Some(CollectedOutput {
            capacity: bounded.bytes,
            available_bytes: kib.wrapping_mul(1024),
            available_inodes: *inodes,
            file,
        })
    }
}

/// `String.lines`: a line ends at `\n`, `\r` or `\r\n`.
fn java_lines(text: &str) -> impl Iterator<Item = &str> {
    let mut rest = text;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        match rest.find(['\n', '\r']) {
            Some(end) => {
                let (line, after) = rest.split_at(end);
                rest = after.strip_prefix("\r\n").or_else(|| after.get(1..)).unwrap_or("");
                Some(line)
            }
            None => Some(std::mem::take(&mut rest)),
        }
    })
}

fn split_whitespace_java(line: &str) -> Vec<&str> {
    line.split([' ', '\t', '\n', '\u{b}', '\u{c}', '\r']).filter(|part| !part.is_empty()).collect()
}

// -------------------------------------------------------------------------------------------------------------
// The archive — `OutputArchive`.

const BLOCK: usize = 512;
/// A PAX header or a long name is a few hundred bytes; more is not a header.
const MAX_META: u64 = 64 * 1024;

/// Why an archive could not be read — `OutputArchive`'s `IOException` messages, which follow "Its output could not
/// be read back: " in the step's failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct UnreadableArchive(pub &'static str);

/// How much of the daemon's archive the runner keeps before it stops reading: the ceiling, a header block, and
/// room for two extended headers. Past that the header has already said "too large".
pub fn archive_budget(ceiling: u64) -> u64 {
    ceiling.saturating_add(MAX_META.saturating_mul(2)).saturating_add(4 * 512)
}

/// `OutputArchive.read`: the one file the archive API answers for a path of a bounded output.
///
/// Written here rather than taken from a library: what is needed is the first entry's header and its bytes, of what
/// Go's `archive/tar` writes — ustar headers, a PAX header overriding the entry's path or size, a GNU long name,
/// base-256 sizes. **The daemon does not follow a link** when it archives a path, so the entry must be a regular
/// file of that name. **The size is checked on the header, before a byte of content is read.**
pub fn read_archive(archive: &[u8], file: &str, ceiling: u64) -> Result<OutputFile, UnreadableArchive> {
    let mut rest = archive;
    let mut pending_name: Option<String> = None;
    let mut pending_size: Option<i64> = None;
    loop {
        let header = match take_block(&mut rest)? {
            None => return Ok(OutputFile::Missing),
            Some(header) if header.iter().all(|byte| *byte == 0) => return Ok(OutputFile::Missing),
            Some(header) => header,
        };
        let kind = header.get(156).copied().unwrap_or(0);
        let mut size = size_of(header)?;
        match kind {
            b'x' | b'L' => {
                let meta = content(&mut rest, size, MAX_META)?;
                if kind == b'L' {
                    pending_name = Some(c_string(meta));
                } else {
                    if let Some(path) = pax_value(meta, "path")? {
                        pending_name = Some(path);
                    }
                    if let Some(value) = pax_value(meta, "size")? {
                        pending_size = Some(parse_pax_size(&value)?);
                    }
                }
                continue;
            }
            b'g' => {
                content(&mut rest, size, MAX_META)?;
                continue;
            }
            _ => {}
        }
        let name = match pending_name.take() {
            Some(name) => name,
            None => name_of(header),
        };
        if let Some(pending) = pending_size {
            size = pending;
        }
        let regular = kind == b'0' || kind == 0;
        if !regular || name != file {
            return Ok(OutputFile::NotRegular);
        }
        // Signed, as Java's `long`: a negative size is never "too large", and `content` refuses it.
        if size > i64::try_from(ceiling).unwrap_or(i64::MAX) {
            return Ok(OutputFile::TooLarge(size.unsigned_abs()));
        }
        return Ok(OutputFile::Read(content(&mut rest, size, ceiling)?.to_vec()));
    }
}

/// A whole block, `None` at the end of the stream, refused when the stream ends inside one.
fn take_block<'a>(rest: &mut &'a [u8]) -> Result<Option<&'a [u8]>, UnreadableArchive> {
    if rest.is_empty() {
        return Ok(None);
    }
    let (block, after) = rest.split_at_checked(BLOCK).ok_or(UnreadableArchive("The output archive ends inside a header."))?;
    *rest = after;
    Ok(Some(block))
}

fn content<'a>(rest: &mut &'a [u8], size: i64, ceiling: u64) -> Result<&'a [u8], UnreadableArchive> {
    if size < 0 || size.unsigned_abs() > ceiling {
        return Err(UnreadableArchive("An entry of the output archive is larger than it may be."));
    }
    let length = usize::try_from(size).map_err(|_| UnreadableArchive("An entry of the output archive is larger than it may be."))?;
    let (bytes, after) = rest.split_at_checked(length).ok_or(UnreadableArchive("The output archive ends inside an entry."))?;
    // The padding to the next block, skipped as `skipNBytes` skips it: what is short of it is the stream's end.
    let padding = match length.checked_rem(BLOCK) {
        Some(0) | None => 0,
        Some(remainder) => BLOCK.saturating_sub(remainder),
    };
    *rest = after.get(padding..).unwrap_or(&[]);
    if after.len() < padding {
        return Err(UnreadableArchive("The output archive ends inside an entry."));
    }
    Ok(bytes)
}

/// Octal, or base-256 when the high bit of the first byte is set — GNU's form for large files.
fn size_of(header: &[u8]) -> Result<i64, UnreadableArchive> {
    let field = header.get(124..136).unwrap_or(&[]);
    let Some((&first, others)) = field.split_first() else { return Ok(0) };
    if first & 0x80 != 0 {
        let impossible = UnreadableArchive("An entry of the output archive declares an impossible size.");
        let mut value = i64::from(first & 0x7f);
        for byte in others {
            value = value.checked_mul(256).and_then(|value| value.checked_add(i64::from(*byte))).ok_or(impossible.clone())?;
        }
        return Ok(value);
    }
    let octal = c_string(field);
    let octal = java::strip(&octal);
    if octal.is_empty() {
        return Ok(0);
    }
    parse_octal(octal).ok_or(UnreadableArchive("An entry of the output archive declares no readable size."))
}

/// `Long.parseLong(text, 8)`: an optional sign, octal digits (any script's, as `Character.digit` reads them),
/// within a long.
fn parse_octal(text: &str) -> Option<i64> {
    parse_signed(text, 8)
}

/// `Long.parseLong(text, radix)`: an optional sign, then digits, accumulated negatively as Java does so that
/// `Long.MIN_VALUE` is read and nothing beyond either end.
fn parse_signed(text: &str, radix: u32) -> Option<i64> {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    if digits.is_empty() {
        return None;
    }
    let magnitude = digits.chars().try_fold(0i64, |value, c| {
        let digit = java::digit(c).filter(|digit| *digit < radix)?;
        value.checked_mul(i64::from(radix))?.checked_sub(i64::from(digit))
    })?;
    if negative { Some(magnitude) } else { magnitude.checked_neg() }
}

/// The name, prefixed by ustar's prefix field when it carries one.
fn name_of(header: &[u8]) -> String {
    let name = c_string(header.get(0..100).unwrap_or(&[]));
    let magic = c_string(header.get(257..263).unwrap_or(&[]));
    if magic.starts_with("ustar") {
        let prefix = c_string(header.get(345..500).unwrap_or(&[]));
        if !prefix.is_empty() {
            return format!("{prefix}/{name}");
        }
    }
    name
}

/// The bytes up to the first NUL, as UTF-8 with Java's replacement of what is not.
fn c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(bytes.get(..end).unwrap_or(&[])).into_owned()
}

/// A PAX record is `"<length> <key>=<value>\n"`, the length counting the record's bytes.
fn pax_value(meta: &[u8], key: &str) -> Result<Option<String>, UnreadableArchive> {
    let malformed = UnreadableArchive("The output archive carries a malformed extended header.");
    let mut rest = meta;
    while !rest.is_empty() {
        let Some(space) = rest.iter().position(|byte| *byte == b' ') else { break };
        let (digits, _) = rest.split_at(space);
        let length: usize = std::str::from_utf8(digits)
            .ok()
            .and_then(vectispire_parse_int)
            .ok_or(malformed.clone())?;
        if length <= space.saturating_add(1) || length > rest.len() {
            return Err(malformed);
        }
        let (record, after) = rest.split_at(length);
        // Between the space and the final byte (the newline, not checked — as Java does not check it).
        let body = record.get(space.saturating_add(1)..length.saturating_sub(1)).unwrap_or(&[]);
        let text = String::from_utf8_lossy(body);
        if let Some((name, value)) = text.split_once('=')
            && !name.is_empty() && name == key {
                return Ok(Some(value.to_owned()));
            }
        rest = after;
    }
    Ok(None)
}

/// `Integer.parseInt` of a PAX length: ASCII digits with an optional sign, within an int; a negative one is no length.
fn vectispire_parse_int(text: &str) -> Option<usize> {
    let digits = text.strip_prefix('+').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return if text.strip_prefix('-').is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())) {
            Some(0)
        } else {
            None
        };
    }
    digits.parse::<i32>().ok().and_then(|value| usize::try_from(value).ok())
}

/// `Long.parseLong(value.strip())` of a PAX size; a negative one is refused by `content`, as Java's `size < 0` is.
fn parse_pax_size(value: &str) -> Result<i64, UnreadableArchive> {
    parse_signed(java::strip(value), 10).ok_or(UnreadableArchive("The output archive carries a malformed extended header."))
}
