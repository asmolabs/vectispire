//! `java.util.zip.ZipInputStream` as JDK 25 reads an archive — entry after entry from the local headers, never from
//! the central directory — with the count `WorkbookReader.CountingZip` adds: the compressed bytes the inflater has
//! consumed for the current entry.
//!
//! **Its reading, not a zip library's**, because the reader's guards are judged on what this stream hands over, in
//! the chunks it hands it: a ratio is compressed bytes as zlib consumed them, 512 at a time, against inflated bytes
//! in reads of at most 8,192; a stored entry is as long as its local header says; the archive ends at the first
//! header that is not a local one, the central directory included, or at a header cut short. A central-directory
//! reader would accept and refuse other files. The inflater is zlib itself (`flate2` on `libz-sys`), the one the
//! JDK calls, so that the bytes consumed are the same bytes.
//!
//! Which exception Java raises is kept apart because the reader answers each in its own words: a `ZipException`
//! (`Malformed`), another `IOException` — an end reached early (`Truncated`) — and the `IllegalArgumentException`
//! `ZipEntry` raises for a header past 65,535 bytes, which the reader does not catch (`Illegal`).

use flate2::{Crc, Decompress, FlushDecompress, Status};

const LOCSIG: u32 = 0x0403_4b50;
const EXTSIG: u32 = 0x0807_4b50;
const LOCHDR: usize = 30;
const EXTHDR: usize = 16;
const ZIP64_EXTHDR: usize = 24;
const ZIP64_MAGICVAL: i64 = 0xFFFF_FFFF;
const EXTID_ZIP64: usize = 0x0001;
const CENHDR: usize = 46;
const MAX_COMBINED_CEN_HEADER_SIZE: usize = 0xFFFF;
/// `InflaterInputStream`'s buffer, and so the most compressed bytes one fill hands the inflater.
const FILL: usize = 512;

pub(crate) const STORED: u16 = 0;
pub(crate) const DEFLATED: u16 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ZipError {
    /// A `ZipException`.
    Malformed,
    /// Any other `IOException`: the archive ended inside something it had started.
    Truncated,
    /// An `IllegalArgumentException`, with its message.
    Illegal(&'static str),
}

/// An entry as its local header states it.
#[derive(Debug, Clone)]
pub(crate) struct ZipEntry {
    pub(crate) name: String,
    pub(crate) method: u16,
    flag: u16,
    crc: i64,
    size: i64,
    csize: i64,
}

impl ZipEntry {
    /// `ZipEntry.isDirectory`: its name ends with a slash.
    pub(crate) fn is_directory(&self) -> bool {
        self.name.ends_with('/')
    }
}

pub(crate) struct ZipInput<'a> {
    file: &'a [u8],
    /// Where the next byte read from the underlying stream is.
    pos: usize,
    entry: Option<ZipEntry>,
    inflater: Decompress,
    /// The inflater's input: `file[input_start..input_end]`, what the last fill handed it and it has not consumed.
    input_start: usize,
    input_end: usize,
    finished: bool,
    pending_output: bool,
    crc: Crc,
    remaining: i64,
    expect_64_bit_data_descriptor: bool,
}

impl<'a> ZipInput<'a> {
    pub(crate) fn new(file: &'a [u8]) -> ZipInput<'a> {
        ZipInput {
            file,
            pos: 0,
            entry: None,
            inflater: Decompress::new(false),
            input_start: 0,
            input_end: 0,
            finished: false,
            pending_output: false,
            crc: Crc::new(),
            remaining: 0,
            expect_64_bit_data_descriptor: false,
        }
    }

    /// `inf.getBytesRead()`: the compressed bytes the current entry's inflater has consumed.
    pub(crate) fn compressed_read(&self) -> u64 {
        self.inflater.total_in()
    }

    /// `getNextEntry`: what is left of the current entry read and discarded, then the next local header, or `None`
    /// where there is none.
    pub(crate) fn next_entry(&mut self) -> Result<Option<ZipEntry>, ZipError> {
        if self.entry.is_some() {
            let mut discarded = [0u8; FILL];
            while self.read(&mut discarded)? != -1 {}
        }
        self.crc.reset();
        self.inflater.reset(false);
        self.input_start = 0;
        self.input_end = 0;
        self.finished = false;
        self.pending_output = false;
        self.entry = self.read_loc()?;
        if let Some(entry) = &self.entry
            && entry.method == STORED
        {
            self.remaining = entry.size;
        }
        Ok(self.entry.clone())
    }

    /// `readFully`: exactly `length` bytes of the underlying stream, or the end reached early.
    fn read_fully(&mut self, length: usize) -> Result<&'a [u8], ZipError> {
        let end = self.pos.checked_add(length).filter(|end| *end <= self.file.len()).ok_or(ZipError::Truncated)?;
        let bytes = self.file.get(self.pos..end).ok_or(ZipError::Truncated)?;
        self.pos = end;
        Ok(bytes)
    }

    fn read_loc(&mut self) -> Result<Option<ZipEntry>, ZipError> {
        // A header cut short ends the archive, as one that is not a local header does.
        let Ok(header) = self.read_fully(LOCHDR) else {
            return Ok(None);
        };
        if u32_at(header, 0) != LOCSIG {
            return Ok(None);
        }
        let flag = u16_at(header, 6);
        let name_length = usize::from(u16_at(header, 26));
        // Both branches decode strictly: the stream's charset is UTF-8 whether or not the entry says so.
        let name = std::str::from_utf8(self.read_fully(name_length)?).map_err(|_| ZipError::Malformed)?.to_owned();
        let name_units: usize = name.chars().map(char::len_utf16).sum();
        if CENHDR.saturating_add(name_units) > MAX_COMBINED_CEN_HEADER_SIZE {
            return Err(ZipError::Illegal("entry name too long"));
        }
        if flag & 1 == 1 {
            return Err(ZipError::Malformed);
        }
        let method = u16_at(header, 8);
        self.expect_64_bit_data_descriptor = false;
        let csize = i64::from(u32_at(header, 18));
        let size = i64::from(u32_at(header, 22));
        let mut entry = ZipEntry { name, method, flag, crc: -1, size: -1, csize: -1 };
        if flag & 8 == 8 {
            if method != DEFLATED {
                return Err(ZipError::Malformed);
            }
        } else {
            entry.crc = i64::from(u32_at(header, 14));
            entry.csize = csize;
            entry.size = size;
        }
        let extra_length = usize::from(u16_at(header, 28));
        if extra_length > 0 {
            let extra = self.read_fully(extra_length)?;
            if CENHDR.saturating_add(name_units).saturating_add(extra.len()) > MAX_COMBINED_CEN_HEADER_SIZE {
                return Err(ZipError::Illegal("invalid extra field length"));
            }
            let zip64 = entry.csize == ZIP64_MAGICVAL || entry.size == ZIP64_MAGICVAL;
            zip64_sizes(&mut entry, extra, zip64);
            self.expect_64_bit_data_descriptor = expect_64_bit_data_descriptor(extra, flag, csize, size);
        }
        Ok(Some(entry))
    }

    /// `read(b, 0, b.len())`: the number of bytes read into `out`, or -1 at the end of the entry.
    pub(crate) fn read(&mut self, out: &mut [u8]) -> Result<i64, ZipError> {
        if out.is_empty() {
            return Ok(0);
        }
        let Some(entry) = self.entry.clone() else {
            return Ok(-1);
        };
        match entry.method {
            DEFLATED => {
                let read = self.inflate(out)?;
                if read == 0 {
                    self.read_end(entry)?;
                    self.entry = None;
                    return Ok(-1);
                }
                self.crc.update(out.get(..read).unwrap_or_default());
                Ok(i64::try_from(read).unwrap_or(i64::MAX))
            }
            STORED => {
                if self.remaining <= 0 {
                    self.entry = None;
                    return Ok(-1);
                }
                let wanted = usize::try_from(self.remaining).map_or(out.len(), |remaining| remaining.min(out.len()));
                let available = self.file.len().saturating_sub(self.pos).min(wanted);
                if available == 0 {
                    return Err(ZipError::Malformed);
                }
                let end = self.pos.saturating_add(available);
                let (Some(chunk), Some(into)) = (self.file.get(self.pos..end), out.get_mut(..available)) else {
                    return Err(ZipError::Malformed);
                };
                self.pos = end;
                into.copy_from_slice(chunk);
                self.crc.update(chunk);
                self.remaining = self.remaining.saturating_sub(i64::try_from(available).unwrap_or(i64::MAX));
                if self.remaining == 0 && entry.crc != i64::from(self.crc.sum()) {
                    return Err(ZipError::Malformed);
                }
                Ok(i64::try_from(available).unwrap_or(i64::MAX))
            }
            _ => Err(ZipError::Malformed),
        }
    }

    /// `InflaterInputStream.read`: one inflate call per read that produces anything, the input refilled 512 bytes
    /// at a time once it is spent and nothing waits in the inflater; 0 at the end of the deflated stream.
    fn inflate(&mut self, out: &mut [u8]) -> Result<usize, ZipError> {
        loop {
            if self.finished {
                return Ok(0);
            }
            if self.input_start == self.input_end && !self.pending_output {
                if self.pos >= self.file.len() {
                    return Err(ZipError::Truncated);
                }
                self.input_start = self.pos;
                self.input_end = self.file.len().min(self.pos.saturating_add(FILL));
                self.pos = self.input_end;
            }
            let (before_in, before_out) = (self.inflater.total_in(), self.inflater.total_out());
            let status = self
                .inflater
                .decompress(
                    self.file.get(self.input_start..self.input_end).unwrap_or_default(),
                    out,
                    FlushDecompress::None,
                )
                .map_err(|_| ZipError::Malformed)?;
            let consumed = usize::try_from(self.inflater.total_in().saturating_sub(before_in)).unwrap_or(usize::MAX);
            let produced = usize::try_from(self.inflater.total_out().saturating_sub(before_out)).unwrap_or(usize::MAX);
            self.input_start = self.input_start.saturating_add(consumed).min(self.input_end);
            self.finished = status == Status::StreamEnd;
            self.pending_output = produced == out.len() && !self.finished;
            if produced > 0 {
                return Ok(produced);
            }
            // zlib makes progress whenever it holds input and room: a call that did neither would loop for ever.
            if consumed == 0 && !self.finished && self.input_start < self.input_end {
                return Err(ZipError::Malformed);
            }
        }
    }

    /// `readEnd`: the inflater's unread input pushed back, the data descriptor read when the header said one
    /// follows, and the sizes and CRC the entry states held to what was inflated.
    fn read_end(&mut self, mut entry: ZipEntry) -> Result<(), ZipError> {
        self.pos = self.input_start;
        self.input_end = self.input_start;
        let written = i64::try_from(self.inflater.total_out()).unwrap_or(i64::MAX);
        let read = i64::try_from(self.inflater.total_in()).unwrap_or(i64::MAX);
        if entry.flag & 8 == 8 {
            if written > ZIP64_MAGICVAL || read > ZIP64_MAGICVAL || self.expect_64_bit_data_descriptor {
                let descriptor = self.read_fully(ZIP64_EXTHDR)?;
                if u32_at(descriptor, 0) == EXTSIG {
                    entry.crc = i64::from(u32_at(descriptor, 4));
                    entry.csize = i64_at(descriptor, 8);
                    entry.size = i64_at(descriptor, 16);
                } else {
                    entry.crc = i64::from(u32_at(descriptor, 0));
                    entry.csize = i64_at(descriptor, 4);
                    entry.size = i64_at(descriptor, 12);
                    self.pos = self.pos.saturating_sub(4);
                }
            } else {
                let descriptor = self.read_fully(EXTHDR)?;
                if u32_at(descriptor, 0) == EXTSIG {
                    entry.crc = i64::from(u32_at(descriptor, 4));
                    entry.csize = i64::from(u32_at(descriptor, 8));
                    entry.size = i64::from(u32_at(descriptor, 12));
                } else {
                    entry.crc = i64::from(u32_at(descriptor, 0));
                    entry.csize = i64::from(u32_at(descriptor, 4));
                    entry.size = i64::from(u32_at(descriptor, 8));
                    self.pos = self.pos.saturating_sub(4);
                }
            }
        }
        if entry.size != written || entry.csize != read || entry.crc != i64::from(self.crc.sum()) {
            return Err(ZipError::Malformed);
        }
        Ok(())
    }
}

/// `ZipEntry.setExtra0` for a local header: only a ZIP64 field of sixteen bytes or more changes what is read —
/// both sizes, when either was the magic value. The time fields it also reads are never used here.
fn zip64_sizes(entry: &mut ZipEntry, extra: &[u8], zip64: bool) {
    // Offsets within a field of at most 65,535 bytes: they never saturate.
    let mut off = 0usize;
    while off.saturating_add(4) < extra.len() {
        let tag = usize::from(u16_at(extra, off));
        let size = usize::from(u16_at(extra, off.saturating_add(2)));
        off = off.saturating_add(4);
        if off.saturating_add(size) > extra.len() {
            break;
        }
        if tag == EXTID_ZIP64 && zip64 && size >= 16 {
            entry.size = i64_at(extra, off);
            entry.csize = i64_at(extra, off.saturating_add(8));
        }
        off = off.saturating_add(size);
    }
}

/// `expect64BitDataDescriptor`: a descriptor follows, a size is the magic value, and a ZIP64 field is present.
fn expect_64_bit_data_descriptor(extra: &[u8], flag: u16, csize: i64, size: i64) -> bool {
    if flag & 8 == 0 || (csize != ZIP64_MAGICVAL && size != ZIP64_MAGICVAL) {
        return false;
    }
    let mut i = 0usize;
    while i.saturating_add(4) < extra.len() {
        let id = usize::from(u16_at(extra, i));
        let size = usize::from(u16_at(extra, i.saturating_add(2)));
        let next = i.saturating_add(4).saturating_add(size);
        if next > extra.len() {
            return false;
        }
        if id == EXTID_ZIP64 {
            return true;
        }
        i = next;
    }
    false
}

/// `N` bytes at `at`; every caller reads within a header it has read whole, and zeros stand for anything past it.
fn word<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    at.checked_add(N)
        .and_then(|end| bytes.get(at..end))
        .and_then(|slice| <[u8; N]>::try_from(slice).ok())
        .unwrap_or([0; N])
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(word(bytes, at))
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(word(bytes, at))
}

/// `get64S`: eight bytes little-endian, as a signed long.
fn i64_at(bytes: &[u8], at: usize) -> i64 {
    i64::from_le_bytes(word(bytes, at))
}
