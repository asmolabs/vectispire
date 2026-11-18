//! FIRST's daily EPSS file — every scored CVE with its probability and percentile — read as a stream and accepted
//! only whole: Java's `EpssFile`, held to `reference/threatintel/domain.json`.
//!
//! **Pulled rather than pushed.** Java hands each batch to a sink; the rows here are written by asynchronous
//! statements, so the caller pulls instead — [`EpssReader::open`], [`header`](EpssReader::header), then
//! [`next_batch`](EpssReader::next_batch) until it answers `None` — and meets the rows, the batches and the refusals
//! in the order Java's sink met them: a partial last batch is handed over **before** the file is refused for being
//! short, and a row that fails drops the batch it was being added to.
//!
//! **Read whole, or not at all**, for the reasons Java's class gives: a damaged gzip stream is refused by its framing
//! and its checksum, a complete archive of half the list by [`MIN_ROWS`] and [`require_comparable`], one malformed
//! row by the row. **Bounded twice**: the inflated bytes are counted ([`MAX_INFLATED_BYTES`]), and a line longer than
//! any row ([`MAX_LINE`]) is refused before it is buffered.

use flate2::{Crc, Decompress, FlushDecompress, Status};
use vectispire_domain::instant::Instant;
use vectispire_domain::java;

use crate::status::is_cve;

/// FIRST's own address for the current file.
pub const DEFAULT_URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
/// The fewest rows a whole file carries.
pub const MIN_ROWS: u64 = 100_000;
/// The most rows accepted.
pub const MAX_ROWS: u64 = 2_000_000;
/// The share of the file in use a new one must carry at least.
pub const MIN_SHARE_OF_PREVIOUS: f64 = 0.9;
/// The inflated file may weigh this much.
pub const MAX_INFLATED_BYTES: u64 = 128 * 1024 * 1024;
/// A row is some thirty characters; a line this long is not one.
pub const MAX_LINE: usize = 256;
/// The column the model version is stored in, in UTF-16 units.
pub const VERSION_MAX: usize = 32;

/// How much is inflated at a time — Java's buffers are 64 KiB, and nothing observable depends on the size.
const CHUNK: usize = 64 * 1024;

/// A file that is not FIRST's EPSS file, or not all of it. Never read as a file without scores.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Unreadable(pub String);

fn unreadable(reason: impl Into<String>) -> Unreadable {
    Unreadable(reason.into())
}

/// The file's first line: the model that scored it, and the day the scores are for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub model_version: String,
    pub score_date: Instant,
}

/// One row: an upper-case CVE, its probability and its percentile, both in [0, 1].
#[derive(Debug, Clone, PartialEq)]
pub struct Score {
    pub cve: String,
    pub score: f64,
    pub percentile: f64,
}

/// `requireComparable`: a file markedly smaller than the one in use is an incomplete export.
pub fn require_comparable(previous_rows: u64, rows: u64) -> Result<(), Unreadable> {
    // `rows < previousRows * 0.9`, in doubles as Java compares them.
    #[allow(clippy::cast_precision_loss)]
    let short = (rows as f64) < (previous_rows as f64) * MIN_SHARE_OF_PREVIOUS;
    if previous_rows > 0 && short {
        return Err(unreadable(format!(
            "the file carries {rows} scores where the one in use carries {previous_rows}: an export that lost a \
             tenth of the population is incomplete; kept the one in use"
        )));
    }
    Ok(())
}

/// The file being read: its lines, the rows counted so far, and where the reading stands.
pub struct EpssReader<'a> {
    lines: Lines<'a>,
    header: Header,
    rows: u64,
    done: bool,
}

impl std::fmt::Debug for EpssReader<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("EpssReader").field("header", &self.header).field("rows", &self.rows).finish()
    }
}

impl<'a> EpssReader<'a> {
    /// The file, gzip or plain, opened and read up to its two header lines.
    pub fn open(body: &'a [u8]) -> Result<EpssReader<'a>, Unreadable> {
        let source = if body.starts_with(&[0x1f, 0x8b]) { Source::gzip(body)? } else { Source::Plain { body, at: 0 } };
        let mut lines = Lines::new(source);
        let header = header(lines.next()?)?;
        let columns = lines.next()?;
        let expected =
            columns.is_some_and(|columns| java::to_lower_root(java::trim(&columns)) == "cve,epss,percentile");
        if !expected {
            return Err(unreadable(
                "the second line is not the header \"cve,epss,percentile\": it is not the EPSS file",
            ));
        }
        Ok(EpssReader { lines, header, rows: 0, done: false })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The rows read so far.
    pub fn rows(&self) -> u64 {
        self.rows
    }

    /// The next batch of at most `size` rows; `None` once the file is read whole. A partial last batch comes first,
    /// then — on the call after it — the refusal of a file too short.
    pub fn next_batch(&mut self, size: usize) -> Result<Option<Vec<Score>>, Unreadable> {
        let size = size.max(1);
        let mut batch = Vec::with_capacity(size.min(CHUNK));
        while !self.done && batch.len() < size {
            let Some(line) = self.lines.next()? else {
                self.done = true;
                break;
            };
            if java::is_blank(&line) {
                continue;
            }
            self.rows = self.rows.saturating_add(1);
            if self.rows > MAX_ROWS {
                return Err(unreadable(format!(
                    "the file carries more than {MAX_ROWS} scores: it is not the EPSS file"
                )));
            }
            batch.push(row(&line, self.lines.number)?);
        }
        if !batch.is_empty() {
            return Ok(Some(batch));
        }
        if self.rows < MIN_ROWS {
            return Err(unreadable(format!(
                "the file carries {} scores; a whole EPSS file carries more than {MIN_ROWS}: it is incomplete",
                self.rows
            )));
        }
        Ok(None)
    }
}

/// `#model_version:v2025.03.14,score_date:2026-09-27T12:00:21Z`: both are required.
fn header(line: Option<String>) -> Result<Header, Unreadable> {
    let Some(rest) = line.as_deref().and_then(|line| line.strip_prefix('#')) else {
        return Err(unreadable(
            "the file does not begin with its \"#model_version:…,score_date:…\" line: it is not the EPSS file, or is \
             one too old to say which model scored it",
        ));
    };
    let mut version: Option<String> = None;
    let mut date: Option<Instant> = None;
    for pair in rest.split(',') {
        let Some((key, value)) = pair.split_once(':') else {
            continue;
        };
        let value = java::trim(value);
        match java::to_lower_root(java::trim(key)).as_str() {
            "model_version" => version = (!value.is_empty()).then(|| value.to_owned()),
            "score_date" => date = score_date(value),
            // A field FIRST adds later is not a reason to refuse the file.
            _ => {}
        }
    }
    let Some(version) = version else {
        return Err(unreadable("the file's first line names no model_version"));
    };
    if java::utf16_len(&version) > VERSION_MAX {
        return Err(unreadable(format!("the file's model_version is longer than {VERSION_MAX} characters")));
    }
    // Refused rather than taken as today: the date is what tells a stale mirror from a fresh file.
    let Some(score_date) = date else {
        return Err(unreadable("the file's first line carries no readable score_date"));
    };
    Ok(Header { model_version: version, score_date })
}

/// `Instant.parse`, or the start of a `LocalDate.parse`d day in UTC.
fn score_date(value: &str) -> Option<Instant> {
    Instant::parse_iso(value).or_else(|| {
        let (year, month, day) = java::iso_local_date(value)?;
        Instant::of_utc(year, u32::from(month), u32::from(day), 0, 0, 0)
    })
}

fn row(line: &str, number: u64) -> Result<Score, Unreadable> {
    let fields: Vec<&str> = line.split(',').collect();
    let [cve, score, percentile] = fields.as_slice() else {
        return Err(unreadable(format!("line {number} has {} fields where a row has three", fields.len())));
    };
    let cve = java::to_upper_root(java::trim(cve));
    if !is_cve(&cve) {
        return Err(unreadable(format!("line {number} does not begin with a CVE identifier")));
    }
    Ok(Score {
        cve,
        score: probability(score, "epss", number)?,
        percentile: probability(percentile, "percentile", number)?,
    })
}

/// A value in [0, 1], or a refusal — never a default: an empty field read as zero would report a measured "no chance".
fn probability(field: &str, column: &str, number: u64) -> Result<f64, Unreadable> {
    let trimmed = java::trim(field);
    let Some(value) = java::parse_double(trimmed) else {
        return Err(unreadable(format!("line {number}: the {column} is not a number")));
    };
    if !(0.0..=1.0).contains(&value) {
        return Err(unreadable(format!("line {number}: the {column} {trimmed} is not within [0, 1]")));
    }
    Ok(value)
}

/// Lines of ASCII, none longer than [`MAX_LINE`]: a line feed ends one, a carriage return is dropped wherever it is,
/// a byte past ASCII reads as U+FFFD as `US_ASCII` decodes it.
struct Lines<'a> {
    source: Source<'a>,
    buffer: Vec<u8>,
    at: usize,
    ended: bool,
    number: u64,
}

impl<'a> Lines<'a> {
    fn new(source: Source<'a>) -> Lines<'a> {
        Lines { source, buffer: Vec::new(), at: 0, ended: false, number: 0 }
    }

    fn byte(&mut self) -> Result<Option<u8>, Unreadable> {
        loop {
            if let Some(&byte) = self.buffer.get(self.at) {
                self.at = self.at.saturating_add(1);
                return Ok(Some(byte));
            }
            if self.ended {
                return Ok(None);
            }
            self.buffer.clear();
            self.at = 0;
            self.ended = !self.source.fill(&mut self.buffer)?;
        }
    }

    fn next(&mut self) -> Result<Option<String>, Unreadable> {
        let Some(mut read) = self.byte()? else {
            return Ok(None);
        };
        self.number = self.number.saturating_add(1);
        let mut line = String::new();
        let mut length = 0usize;
        loop {
            if read == b'\n' {
                break;
            }
            if read != b'\r' {
                if length == MAX_LINE {
                    return Err(unreadable(format!(
                        "line {} is longer than {MAX_LINE} characters: it is not a row of the EPSS file",
                        self.number
                    )));
                }
                line.push(if read.is_ascii() { char::from(read) } else { '\u{fffd}' });
                length = length.saturating_add(1);
            }
            match self.byte()? {
                Some(next) => read = next,
                None => break,
            }
        }
        Ok(Some(line))
    }
}

/// Where the bytes come from: the body as it is, or inflated member by member.
enum Source<'a> {
    Plain { body: &'a [u8], at: usize },
    Gzip(Box<Gzip<'a>>),
}

impl<'a> Source<'a> {
    fn gzip(body: &'a [u8]) -> Result<Source<'a>, Unreadable> {
        let start = gzip_header(body).map_err(broken)?;
        Ok(Source::Gzip(Box::new(Gzip {
            body,
            at: start,
            inflater: Decompress::new(false),
            crc: Crc::new(),
            state: Member::Data,
            inflated: 0,
        })))
    }

    /// Appends the next bytes; `false` at the end. The inflated bytes are counted against [`MAX_INFLATED_BYTES`].
    fn fill(&mut self, out: &mut Vec<u8>) -> Result<bool, Unreadable> {
        match self {
            Source::Plain { body, at } => {
                let Some(rest) = body.get(*at..).filter(|rest| !rest.is_empty()) else {
                    return Ok(false);
                };
                let take = rest.len().min(CHUNK);
                out.extend_from_slice(rest.get(..take).unwrap_or_default());
                *at = at.saturating_add(take);
                ceiling(at_most(*at))?;
                Ok(true)
            }
            Source::Gzip(gzip) => gzip.fill(out),
        }
    }
}

fn at_most(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

fn count(total: &mut u64, more: usize) -> Result<(), Unreadable> {
    *total = total.saturating_add(at_most(more));
    ceiling(*total)
}

fn ceiling(total: u64) -> Result<(), Unreadable> {
    if total > MAX_INFLATED_BYTES {
        return Err(unreadable(format!("the file inflates past {MAX_INFLATED_BYTES} bytes: it is not the EPSS file")));
    }
    Ok(())
}

/// Why a gzip stream is broken, in the words of the exception Java's `GZIPInputStream` throws — an `EOFException`'s
/// message is `null`, and Java prints it so.
#[derive(Debug)]
enum Broken {
    Eof,
    Said(String),
}

fn broken(why: Broken) -> Unreadable {
    let message = match why {
        Broken::Eof => "null".to_owned(),
        Broken::Said(message) => message,
    };
    unreadable(format!("the file is not a whole gzip archive ({message}): it was cut short or damaged"))
}

enum Member {
    Data,
    Trailer,
    Done,
}

/// `GZIPInputStream` over zlib: a member's header, its deflate data, its trailer, then the next member if what follows
/// is one — and, as Java reads it, the end if what follows is not.
struct Gzip<'a> {
    body: &'a [u8],
    at: usize,
    inflater: Decompress,
    crc: Crc,
    state: Member,
    inflated: u64,
}

impl Gzip<'_> {
    fn fill(&mut self, out: &mut Vec<u8>) -> Result<bool, Unreadable> {
        loop {
            match self.state {
                Member::Done => return Ok(false),
                Member::Trailer => self.trailer()?,
                Member::Data => {
                    let input = self.body.get(self.at..).unwrap_or_default();
                    let mut chunk = vec![0u8; CHUNK];
                    let before_in = self.inflater.total_in();
                    let before_out = self.inflater.total_out();
                    let status =
                        self.inflater.decompress(input, &mut chunk, FlushDecompress::None).map_err(|error| {
                            broken(Broken::Said(error.message().unwrap_or("Invalid ZLIB data format").to_owned()))
                        })?;
                    let consumed = usize::try_from(self.inflater.total_in().saturating_sub(before_in)).unwrap_or(0);
                    let produced = usize::try_from(self.inflater.total_out().saturating_sub(before_out)).unwrap_or(0);
                    self.at = self.at.saturating_add(consumed);
                    let bytes = chunk.get(..produced).unwrap_or_default();
                    self.crc.update(bytes);
                    count(&mut self.inflated, produced)?;
                    out.extend_from_slice(bytes);
                    if matches!(status, Status::StreamEnd) {
                        self.state = Member::Trailer;
                    }
                    if produced > 0 {
                        return Ok(true);
                    }
                    if consumed == 0 && !matches!(status, Status::StreamEnd) {
                        // Nothing produced and nothing more to give it: the data was cut short.
                        return Err(broken(Broken::Said("Unexpected end of ZLIB input stream".to_owned())));
                    }
                }
            }
        }
    }

    /// The CRC-32 and the size modulo 2³², then the next member — or the end, where what follows is not one.
    fn trailer(&mut self) -> Result<(), Unreadable> {
        let crc = little_endian(self.body, self.at).ok_or_else(|| broken(Broken::Eof))?;
        let size = little_endian(self.body, self.at.saturating_add(4)).ok_or_else(|| broken(Broken::Eof))?;
        let written = u32::try_from(self.inflater.total_out() & 0xffff_ffff).unwrap_or(0);
        if crc != self.crc.sum() || size != written {
            return Err(broken(Broken::Said("Corrupt GZIP trailer".to_owned())));
        }
        self.at = self.at.saturating_add(8);
        let rest = self.body.get(self.at..).unwrap_or_default();
        self.state = match (!rest.is_empty()).then(|| gzip_header(rest)) {
            Some(Ok(length)) => {
                self.at = self.at.saturating_add(length);
                self.inflater.reset(false);
                self.crc.reset();
                Member::Data
            }
            // Java ends the stream where what follows is not a gzip member.
            Some(Err(_)) | None => Member::Done,
        };
        Ok(())
    }
}

fn little_endian(body: &[u8], at: usize) -> Option<u32> {
    let bytes: [u8; 4] = body.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// `GZIPInputStream.readHeader`: the header's length, or why it is not one.
fn gzip_header(body: &[u8]) -> Result<usize, Broken> {
    let byte = |at: usize| body.get(at).copied().ok_or(Broken::Eof);
    if byte(0)? != 0x1f || byte(1)? != 0x8b {
        return Err(Broken::Said("Not in GZIP format".to_owned()));
    }
    if byte(2)? != 8 {
        return Err(Broken::Said("Unsupported compression method".to_owned()));
    }
    let flags = byte(3)?;
    byte(9)?;
    let mut at = 10usize;
    if flags & 0x04 != 0 {
        let length = usize::from(byte(at)?) | (usize::from(byte(at.saturating_add(1))?) << 8);
        at = at.saturating_add(2).saturating_add(length);
        if body.len() < at {
            return Err(Broken::Eof);
        }
    }
    for flag in [0x08, 0x10] {
        if flags & flag != 0 {
            loop {
                let read = byte(at)?;
                at = at.saturating_add(1);
                if read == 0 {
                    break;
                }
            }
        }
    }
    if flags & 0x02 != 0 {
        let mut crc = Crc::new();
        crc.update(body.get(..at).unwrap_or_default());
        let stored = u32::from(byte(at)?) | (u32::from(byte(at.saturating_add(1))?) << 8);
        if stored != crc.sum() & 0xffff {
            return Err(Broken::Said("Corrupt GZIP header".to_owned()));
        }
        at = at.saturating_add(2);
    }
    Ok(at)
}
