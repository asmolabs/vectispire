//! A mount's content as it crosses into a scan pod and back, over `exec` (decision 0045 §4) — what a bind mount did on
//! Docker (`MountArchives`).
//!
//! **Every entry goes in dated 1970.** What the scanner writes is then the only thing newer than a day in the pod's
//! copy, which is how `find -mtime -1` picks out what to bring back without a marker file racing the scanner's first
//! second. A scanner reading modification times reads a constant; none of the pinned ones does.
//!
//! **Coming back, only regular files, and only inside the mount.** What the pod sends is written by a scanner that
//! read a hostile tree: an absolute name, a `..`, a link, or a path through a link already in the workspace would put
//! a file where nobody asked for one. Each is refused, and the step fails rather than half-copies. A sparse entry is
//! refused and the total capped, so what comes back can never be larger than what crossed the wire.
//!
//! **Written here rather than taken from a crate**: the reader is the agent's one parser of what a compromised scanner
//! chose to send, and it reads exactly the entries Java's reader (commons-compress) reads, refusing the rest — held to
//! it by `reference/kubernetes/archives.json`, archives commons-compress wrote. The writer's output is read by the
//! pinned busybox `tar`, which the cluster tests run.

use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

const BLOCK: usize = 512;
/// The ustar name field.
const NAME: std::ops::Range<usize> = 0..100;
const MODE: std::ops::Range<usize> = 100..108;
const UID: std::ops::Range<usize> = 108..116;
const GID: std::ops::Range<usize> = 116..124;
const SIZE: std::ops::Range<usize> = 124..136;
const MTIME: std::ops::Range<usize> = 136..148;
const CHECKSUM: std::ops::Range<usize> = 148..156;
const TYPE: usize = 156;
const LINK: std::ops::Range<usize> = 157..257;
const MAGIC: std::ops::Range<usize> = 257..265;
const PREFIX: std::ops::Range<usize> = 345..500;
/// The GNU magic and version — `ustar  \0` — under which a long name travels as an `L` entry before its own.
const GNU_MAGIC: &[u8; 8] = b"ustar  \0";
const USTAR_MAGIC: &[u8; 6] = b"ustar\0";
/// The largest size the octal field holds: eleven digits.
const OCTAL_SIZE_MAX: u64 = 0o77_777_777_777;
/// What a long name or a PAX header may be: names are paths, and a header claiming more is not one.
const META_BYTES: u64 = 64 * 1024;

/// The name `source`'s content has under its subdirectory: empty for a directory, its own name for a file.
pub fn name_of(source: &Path) -> String {
    let directory = std::fs::symlink_metadata(source).is_ok_and(|metadata| metadata.is_dir());
    if directory { String::new() } else { file_name(source) }
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Writes `source` — a directory's content, or one file — as a tar archive.
pub fn write(source: &Path, out: &mut impl Write) -> io::Result<()> {
    let directory = std::fs::symlink_metadata(source)?.is_dir();
    if directory {
        let mut entries = Vec::new();
        walk(source, source, &mut entries)?;
        for (path, name) in entries {
            add(out, &path, &name)?;
        }
    } else {
        add(out, source, &file_name(source))?;
    }
    // The end of the archive: two empty blocks.
    out.write_all(&[0u8; BLOCK])?;
    out.write_all(&[0u8; BLOCK])?;
    out.flush()
}

/// Every path under `directory`, links not followed, each directory before what it holds, in name order.
fn walk(root: &Path, directory: &Path, into: &mut Vec<(PathBuf, String)>) -> io::Result<()> {
    let mut children: Vec<PathBuf> =
        std::fs::read_dir(directory)?.map(|entry| entry.map(|entry| entry.path())).collect::<io::Result<_>>()?;
    children.sort();
    for child in children {
        let relative = child.strip_prefix(root).map_err(io::Error::other)?;
        let name = relative.to_string_lossy().replace('\\', "/");
        let is_directory = std::fs::symlink_metadata(&child)?.is_dir();
        into.push((child.clone(), name));
        if is_directory {
            walk(root, &child, into)?;
        }
    }
    Ok(())
}

fn add(out: &mut impl Write, path: &Path, name: &str) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    let kind = metadata.file_type();
    let mode = permissions(&metadata);
    if kind.is_symlink() {
        let target = std::fs::read_link(path)?.to_string_lossy().into_owned();
        header(out, name, b'2', 0o777, 0, &target)
    } else if kind.is_dir() {
        header(out, &format!("{name}/"), b'5', mode, 0, "")
    } else if kind.is_file() {
        let size = metadata.len();
        header(out, name, b'0', mode, size, "")?;
        let mut file = std::fs::File::open(path)?;
        let copied = io::copy(&mut (&mut file).take(size), out)?;
        if copied != size {
            return Err(io::Error::other(format!("{name} changed while it was copied.")));
        }
        pad(out, size)
    } else {
        // A device or a FIFO in a workspace: git stores neither, so something else put it there.
        Err(io::Error::other(format!("{name} is neither a file, a directory nor a link.")))
    }
}

fn permissions(metadata: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        0o644
    }
}

/// One entry's header, preceded by GNU `L`/`K` entries for a name or a link longer than its field.
fn header(out: &mut impl Write, name: &str, kind: u8, mode: u32, size: u64, link: &str) -> io::Result<()> {
    if name.len() > NAME.len() {
        long(out, b'L', name)?;
    }
    if link.len() > LINK.len() {
        long(out, b'K', link)?;
    }
    let mut block = [0u8; BLOCK];
    put(&mut block, NAME, name.as_bytes());
    put(&mut block, MODE, octal(u64::from(mode), MODE.len()).as_bytes());
    put(&mut block, UID, octal(0, UID.len()).as_bytes());
    put(&mut block, GID, octal(0, GID.len()).as_bytes());
    size_field(&mut block, size);
    // Dated 1970: see the module's comment.
    put(&mut block, MTIME, octal(0, MTIME.len()).as_bytes());
    if let Some(flag) = block.get_mut(TYPE) {
        *flag = kind;
    }
    put(&mut block, LINK, link.as_bytes());
    put(&mut block, MAGIC, GNU_MAGIC);
    seal(&mut block);
    out.write_all(&block)
}

/// A GNU long name (`L`) or long link (`K`): the text, NUL-terminated, as the next entry's.
fn long(out: &mut impl Write, kind: u8, text: &str) -> io::Result<()> {
    let length = u64::try_from(text.len()).unwrap_or(u64::MAX).saturating_add(1);
    let mut block = [0u8; BLOCK];
    put(&mut block, NAME, b"././@LongLink");
    put(&mut block, MODE, octal(0, MODE.len()).as_bytes());
    put(&mut block, UID, octal(0, UID.len()).as_bytes());
    put(&mut block, GID, octal(0, GID.len()).as_bytes());
    size_field(&mut block, length);
    put(&mut block, MTIME, octal(0, MTIME.len()).as_bytes());
    if let Some(flag) = block.get_mut(TYPE) {
        *flag = kind;
    }
    put(&mut block, MAGIC, GNU_MAGIC);
    seal(&mut block);
    out.write_all(&block)?;
    out.write_all(text.as_bytes())?;
    out.write_all(&[0])?;
    pad(out, length)
}

/// The size, in octal while it fits and in GNU's base-256 past it — a file of 8 GiB or more.
fn size_field(block: &mut [u8; BLOCK], size: u64) {
    if size <= OCTAL_SIZE_MAX {
        put(block, SIZE, octal(size, SIZE.len()).as_bytes());
        return;
    }
    let mut field = [0u8; 12];
    if let Some(marker) = field.first_mut() {
        *marker = 0x80;
    }
    for (slot, byte) in field.iter_mut().skip(4).zip(size.to_be_bytes()) {
        *slot = byte;
    }
    put(block, SIZE, &field);
}

/// `value` in octal, zero-padded to `width - 1` digits and NUL-terminated.
fn octal(value: u64, width: usize) -> String {
    format!("{value:0>digits$o}", digits = width.saturating_sub(1))
}

fn put(block: &mut [u8; BLOCK], range: std::ops::Range<usize>, bytes: &[u8]) {
    if let Some(field) = block.get_mut(range) {
        for (slot, byte) in field.iter_mut().zip(bytes) {
            *slot = *byte;
        }
    }
}

/// The checksum: the sum of the header's bytes with its own field read as spaces, six octal digits, NUL, space.
fn seal(block: &mut [u8; BLOCK]) {
    put(block, CHECKSUM, b"        ");
    let sum = block.iter().fold(0u32, |sum, byte| sum.saturating_add(u32::from(*byte)));
    put(block, CHECKSUM, format!("{sum:06o}\0 ").as_bytes());
}

/// What follows `size` bytes of data to the next block.
fn padding(size: u64) -> u64 {
    let block = u64::try_from(BLOCK).unwrap_or(512);
    size.checked_rem(block).map_or(0, |rest| if rest == 0 { 0 } else { block.saturating_sub(rest) })
}

fn pad(out: &mut impl Write, size: u64) -> io::Result<()> {
    let zeros = [0u8; BLOCK];
    let length = usize::try_from(padding(size)).unwrap_or(0);
    out.write_all(zeros.get(..length).unwrap_or_default())
}

// ------------------------------------------------------------------------------------------------- reading back

/// One entry as the reader sees it, the long names and the PAX headers applied.
struct Entry {
    name: String,
    kind: u8,
    size: u64,
    sparse: bool,
}

impl Entry {
    /// `TarArchiveEntry.isDirectory`: the directory flag, or a name ending with a slash.
    fn directory(&self) -> bool {
        self.kind == b'5' || self.name.ends_with('/')
    }

    /// A regular file by its type flag — `'0'` or the old `NUL`. Not by its name: commons-compress's `isFile()`
    /// answers true for a link, a device or a FIFO whose name does not end with a slash, which let a link through
    /// on the Java side, and was caught there.
    fn regular(&self) -> bool {
        self.kind == b'0' || self.kind == 0
    }
}

/// Writes into `destination` the regular files of `archive`, refusing anything else; the files written, relative to
/// `destination`.
pub fn extract_written(archive: impl Read, destination: &Path, ceiling: u64) -> io::Result<Vec<String>> {
    let root = destination.canonicalize()?;
    let mut reader = Archive { input: archive };
    let mut written = Vec::new();
    let mut total: u64 = 0;
    while let Some(entry) = reader.next_entry()? {
        let name = entry.name.clone();
        if entry.directory() {
            reader.skip(entry.size)?;
            continue;
        }
        // A sparse entry expands to its declared size from a few bytes: refused, and the total capped (review of
        // 2026-10-26).
        if entry.sparse {
            return Err(refused(format!("It wrote {name} as a sparse file, which is not brought back.")));
        }
        total = total.saturating_add(entry.size);
        if total > ceiling {
            return Err(refused(format!("It wrote more than {ceiling} bytes into its workspace.")));
        }
        if !entry.regular() {
            return Err(refused(format!(
                "It wrote {name}, which is not a regular file; nothing is brought back but files."
            )));
        }
        let target = normalize(&root.join(&name));
        if name.starts_with('/') || !target.starts_with(&root) || target == root {
            return Err(refused(format!("It wrote {name}, a name outside its mount.")));
        }
        // Through no link, existing or not: a link in the workspace would carry the write elsewhere.
        let parent = target.parent().unwrap_or(&root);
        let mut at = root.clone();
        for part in parent.strip_prefix(&root).map_err(io::Error::other)?.components() {
            at.push(part);
            if std::fs::symlink_metadata(&at).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
                let shown = at.strip_prefix(&root).map_err(io::Error::other)?.display().to_string();
                return Err(refused(format!("It wrote {name} through the link {shown}.")));
            }
        }
        if std::fs::symlink_metadata(&target).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(refused(format!("It wrote {name} over a link.")));
        }
        std::fs::create_dir_all(parent)?;
        // Replaced, as `REPLACE_EXISTING` replaces: the old file removed, a new one created — never written through.
        if std::fs::symlink_metadata(&target).is_ok() {
            std::fs::remove_file(&target)?;
        }
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&target)?;
        reader.copy(entry.size, &mut file)?;
        written.push(target.strip_prefix(&root).map_err(io::Error::other)?.display().to_string());
    }
    Ok(written)
}

fn refused(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// `Path.normalize`, lexically: `.` dropped, `..` taking its parent away — never past the root.
fn normalize(path: &Path) -> PathBuf {
    let mut normal = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normal.pop() {
                    normal.push("..");
                }
            }
            other => normal.push(other),
        }
    }
    normal
}

struct Archive<R> {
    input: R,
}

impl<R: Read> Archive<R> {
    /// The next entry with its metadata applied, or `None` at the end — a block of zeros, or the stream's end.
    fn next_entry(&mut self) -> io::Result<Option<Entry>> {
        let mut long_name: Option<String> = None;
        let mut pax_path: Option<String> = None;
        let mut pax_size: Option<u64> = None;
        let mut pax_sparse = false;
        loop {
            let mut block = [0u8; BLOCK];
            if !self.block(&mut block)? || block.iter().all(|byte| *byte == 0) {
                return Ok(None);
            }
            verify(&block)?;
            let kind = block.get(TYPE).copied().unwrap_or(0);
            let size = size_of(&block)?;
            match kind {
                // GNU long name, and long link name (read and dropped: a link is refused whatever it names).
                b'L' | b'K' => {
                    let text = self.meta(size)?;
                    if kind == b'L' {
                        long_name = Some(String::from_utf8_lossy(until_nul(&text)).into_owned());
                    }
                }
                // PAX: this entry's, or every following one's.
                b'x' | b'g' => {
                    let text = self.meta(size)?;
                    if kind == b'x' {
                        for (key, value) in pax_records(&text) {
                            match key.as_str() {
                                "path" => pax_path = Some(value),
                                "size" => pax_size = value.parse().ok(),
                                key if key.starts_with("GNU.sparse.") => pax_sparse = true,
                                _ => {}
                            }
                        }
                    }
                }
                _ => {
                    let name = pax_path.or(long_name).unwrap_or_else(|| ustar_name(&block));
                    let size = pax_size.unwrap_or(size);
                    return Ok(Some(Entry { name, kind, size, sparse: kind == b'S' || pax_sparse }));
                }
            }
        }
    }

    /// One block, or `false` at the stream's end. A stream cut inside a block is broken.
    fn block(&mut self, block: &mut [u8; BLOCK]) -> io::Result<bool> {
        let mut filled = 0;
        while filled < BLOCK {
            let read = self.input.read(block.get_mut(filled..).unwrap_or_default())?;
            if read == 0 {
                return if filled == 0 { Ok(false) } else { Err(cut()) };
            }
            filled = filled.saturating_add(read);
        }
        Ok(true)
    }

    /// A long name's or a PAX header's content, bounded.
    fn meta(&mut self, size: u64) -> io::Result<Vec<u8>> {
        if size > META_BYTES {
            return Err(refused("A tar header of the copy back is larger than any name.".to_owned()));
        }
        let mut text = Vec::new();
        self.copy(size, &mut text)?;
        Ok(text)
    }

    /// `size` bytes of data to `out`, then the padding.
    fn copy(&mut self, size: u64, out: &mut impl Write) -> io::Result<()> {
        let copied = io::copy(&mut (&mut self.input).take(size), out)?;
        if copied != size {
            return Err(cut());
        }
        self.discard(padding(size))
    }

    /// An entry's data unread.
    fn skip(&mut self, size: u64) -> io::Result<()> {
        self.copy(size, &mut io::sink())
    }

    fn discard(&mut self, count: u64) -> io::Result<()> {
        let skipped = io::copy(&mut (&mut self.input).take(count), &mut io::sink())?;
        if skipped == count { Ok(()) } else { Err(cut()) }
    }
}

fn cut() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "The copy back ended inside an entry.")
}

/// The header's checksum, as an unsigned or a signed sum — tar writers have used both.
fn verify(block: &[u8; BLOCK]) -> io::Result<()> {
    let recorded = block.get(CHECKSUM).map(parse_octal).unwrap_or(None);
    let (mut unsigned, mut signed) = (0u64, 0i64);
    for (index, byte) in block.iter().enumerate() {
        let byte = if CHECKSUM.contains(&index) { b' ' } else { *byte };
        unsigned = unsigned.saturating_add(u64::from(byte));
        signed = signed.saturating_add(i64::from(i8::from_ne_bytes([byte])));
    }
    let matches = recorded.is_some_and(|sum| sum == unsigned || i64::try_from(sum).is_ok_and(|sum| sum == signed));
    if matches {
        Ok(())
    } else {
        Err(refused("The copy back is not a tar archive: a header's checksum is wrong.".into()))
    }
}

/// An entry's size: octal, or GNU's base-256 for a large one.
fn size_of(block: &[u8; BLOCK]) -> io::Result<u64> {
    let field = block.get(SIZE).unwrap_or_default();
    if let Some((first, rest)) = field.split_first()
        && first & 0x80 != 0
    {
        // Base-256, big-endian, the marker bit off: a negative one is no size.
        if first & 0x40 != 0 {
            return Err(refused("A tar entry of the copy back declares a negative size.".to_owned()));
        }
        let mut value: u64 = u64::from(first & 0x3f);
        for byte in rest {
            value = value
                .checked_mul(256)
                .and_then(|shifted| shifted.checked_add(u64::from(*byte)))
                .ok_or_else(|| refused("A tar entry of the copy back declares an impossible size.".to_owned()))?;
        }
        return Ok(value);
    }
    parse_octal(field).ok_or_else(|| refused("A tar entry of the copy back has no readable size.".to_owned()))
}

/// An octal field: leading spaces, digits, then a space or a NUL. Empty reads as zero, as tar writers leave it.
fn parse_octal(field: &[u8]) -> Option<u64> {
    let text = until_nul(field);
    let text = std::str::from_utf8(text).ok()?.trim_matches(' ');
    if text.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(text, 8).ok()
}

fn until_nul(bytes: &[u8]) -> &[u8] {
    bytes.split(|byte| *byte == 0).next().unwrap_or_default()
}

/// The name of a header with no long name: the POSIX prefix and name, or the GNU name alone (its prefix area holds
/// other fields).
fn ustar_name(block: &[u8; BLOCK]) -> String {
    let name = String::from_utf8_lossy(until_nul(block.get(NAME).unwrap_or_default())).into_owned();
    let posix = block.get(MAGIC).is_some_and(|magic| magic.starts_with(USTAR_MAGIC));
    let prefix = block.get(PREFIX).map(until_nul).unwrap_or_default();
    if posix && !prefix.is_empty() { format!("{}/{name}", String::from_utf8_lossy(prefix)) } else { name }
}

/// PAX records — `<length> <key>=<value>\n` — read as far as they are well formed.
fn pax_records(text: &[u8]) -> Vec<(String, String)> {
    let mut records = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let Some(space) = rest.iter().position(|byte| *byte == b' ') else { break };
        let Some(length) = std::str::from_utf8(rest.get(..space).unwrap_or_default()).ok().and_then(|n| n.parse().ok())
        else {
            break;
        };
        let Some(record) = rest.get(..length) else { break };
        let body = record.get(space.saturating_add(1)..).unwrap_or_default();
        let body = body.strip_suffix(b"\n").unwrap_or(body);
        if let Some(equals) = body.iter().position(|byte| *byte == b'=') {
            let key = String::from_utf8_lossy(body.get(..equals).unwrap_or_default()).into_owned();
            let value = String::from_utf8_lossy(body.get(equals.saturating_add(1)..).unwrap_or_default()).into_owned();
            records.push((key, value));
        }
        rest = rest.get(length..).unwrap_or_default();
        if length == 0 {
            break;
        }
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> tempfile::TempDir {
        let tree = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tree.path().join("source/deep")).unwrap();
        std::fs::write(tree.path().join("source/main.py"), "print('hello')\n").unwrap();
        std::fs::write(tree.path().join("source/deep/empty"), "").unwrap();
        let long = format!("source/deep/{}.txt", "n".repeat(120));
        std::fs::write(tree.path().join(&long), vec![b'x'; 1500]).unwrap();
        std::os::unix::fs::symlink("main.py", tree.path().join("source/link")).unwrap();
        tree
    }

    /// What goes in is a tar archive: each entry in its block, dated 1970, a long name before its entry, padded, closed
    /// by two empty blocks — read back here entry by entry, with the reader that refuses what a scanner could forge.
    #[test]
    fn a_tree_goes_in_as_a_tar_archive_dated_1970() {
        let tree = tree();
        let mut archive = Vec::new();
        write(tree.path(), &mut archive).unwrap();
        assert_eq!(archive.len() % BLOCK, 0, "whole blocks");
        assert!(archive.ends_with(&[0u8; 2 * BLOCK]), "two empty blocks end it");

        let mut reader = Archive { input: &archive[..] };
        let mut seen = Vec::new();
        while let Some(entry) = reader.next_entry().unwrap() {
            let mut content = Vec::new();
            reader.copy(entry.size, &mut content).unwrap();
            seen.push((entry.name.clone(), char::from(entry.kind), content.len()));
        }
        let long = format!("source/deep/{}.txt", "n".repeat(120));
        assert_eq!(
            seen,
            vec![
                ("source/".to_owned(), '5', 0),
                ("source/deep/".to_owned(), '5', 0),
                ("source/deep/empty".to_owned(), '0', 0),
                (long, '0', 1500),
                ("source/link".to_owned(), '2', 0),
                ("source/main.py".to_owned(), '0', 15),
            ]
        );
        let first = archive.get(..BLOCK).unwrap();
        assert_eq!(first.get(MTIME).unwrap(), b"00000000000\0", "dated 1970");
        assert_eq!(first.get(MAGIC).unwrap(), GNU_MAGIC);

        let single = tempfile::tempdir().unwrap();
        let mut one = Vec::new();
        write(&tree.path().join("source/main.py"), &mut one).unwrap();
        let mut reader = Archive { input: &one[..] };
        assert_eq!(reader.next_entry().unwrap().map(|entry| entry.name), Some("main.py".to_owned()));
        drop(single);
    }

    /// What the holder sends back is read only as a well-formed archive: a header whose checksum is wrong is refused.
    #[test]
    fn a_header_with_a_wrong_checksum_is_refused() {
        let destination = tempfile::tempdir().unwrap();
        let mut archive = Vec::new();
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("report.json"), "[]").unwrap();
        write(source.path(), &mut archive).unwrap();
        assert_eq!(extract_written(&archive[..], destination.path(), 1024).unwrap(), vec!["report.json"]);

        if let Some(byte) = archive.get_mut(NAME.start) {
            *byte = b'R';
        }
        let refused = extract_written(&archive[..], destination.path(), 1024).unwrap_err();
        assert!(refused.to_string().contains("checksum"), "{refused}");
    }

    /// A size past the octal field's eleven digits is written in base-256, and read back.
    #[test]
    fn a_size_past_eight_gibibytes_is_written_in_base_256() {
        let mut block = [0u8; BLOCK];
        size_field(&mut block, 9 * 1024 * 1024 * 1024);
        assert_eq!(block.get(SIZE).and_then(|field| field.first()), Some(&0x80));
        assert_eq!(size_of(&block).unwrap(), 9 * 1024 * 1024 * 1024);
        size_field(&mut block, OCTAL_SIZE_MAX);
        assert_eq!(size_of(&block).unwrap(), OCTAL_SIZE_MAX);
    }
}
