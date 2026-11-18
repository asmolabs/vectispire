//! `DocumentZip`: a zip written the same way every time, byte for byte what Java's `ZipOutputStream` writes for the
//! same entries — the entries in the order given, each dated 1980-02-01 00:00 as a local date-time, no extra field,
//! no comment (decision 0032 §10).
//!
//! **Java's layout, reproduced field by field**: every name flagged UTF-8 (`ZipOutputStream`'s charset is UTF-8, so
//! bit 11 is always set); a deflated entry flagged as followed by a data descriptor (bit 3), its sizes and CRC
//! zero in the local header, the descriptor signed; a stored one with them in the header; version 2.0 to extract a
//! deflated entry, 1.0 a stored one, and the same "made by"; no external attributes. A directory is deflated
//! whatever its source said, as Java writes one. The deflate stream is zlib's at the default level, raw — the
//! `Deflater` the JDK hands its zlib — so the bytes agree as long as both sides link a zlib that deflates alike,
//! which every zlib 1.2.x and 1.3.x does at level 6.

use flate2::{Compress, Compression, Crc, FlushCompress, Status};

const LOCSIG: u32 = 0x0403_4b50;
const EXTSIG: u32 = 0x0807_4b50;
const CENSIG: u32 = 0x0201_4b50;
const ENDSIG: u32 = 0x0605_4b50;
const USE_UTF8: u16 = 0x800;
/// 1980-02-01 00:00, as `ZipEntry.setTimeLocal` packs it: the date in the high half, midnight in the low.
const ENTRY_DOS_TIME: u32 = (2 << 21) | (1 << 16);

/// An entry to write; `stored` keeps it uncompressed, as its source archive had it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub bytes: Vec<u8>,
    pub stored: bool,
    pub directory: bool,
}

impl Entry {
    pub fn of(bytes: Vec<u8>) -> Entry {
        Entry { bytes, stored: false, directory: false }
    }
}

/// `DocumentZip.of`: the archive of `entries`, in their order. Names are unique, as the `SequencedMap` Java takes
/// makes them; a repeated name here is a caller's defect, refused as `ZipOutputStream` refuses it.
pub fn of(entries: &[(String, Entry)]) -> Result<Vec<u8>, DuplicateEntry> {
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    for (index, (name, entry)) in entries.iter().enumerate() {
        if entries.iter().take(index).any(|(earlier, _)| earlier == name) {
            return Err(DuplicateEntry(name.clone()));
        }
        let offset = u32::try_from(out.len()).unwrap_or(u32::MAX);
        let stored = entry.stored && !entry.directory;
        let crc = crc32(&entry.bytes);
        let size = u32::try_from(entry.bytes.len()).unwrap_or(u32::MAX);
        let (version, flag, method) = if stored { (10u16, USE_UTF8, 0u16) } else { (20, USE_UTF8 | 8, 8) };
        let data = if stored { entry.bytes.clone() } else { deflate(&entry.bytes) };
        let compressed = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let name_bytes = name.as_bytes();
        let name_length = u16::try_from(name_bytes.len()).unwrap_or(u16::MAX);

        put32(&mut out, LOCSIG);
        put16(&mut out, version);
        put16(&mut out, flag);
        put16(&mut out, method);
        put32(&mut out, ENTRY_DOS_TIME);
        if stored {
            put32(&mut out, crc);
            put32(&mut out, compressed);
            put32(&mut out, size);
        } else {
            put32(&mut out, 0);
            put32(&mut out, 0);
            put32(&mut out, 0);
        }
        put16(&mut out, name_length);
        put16(&mut out, 0);
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&data);
        if !stored {
            put32(&mut out, EXTSIG);
            put32(&mut out, crc);
            put32(&mut out, compressed);
            put32(&mut out, size);
        }

        put32(&mut central, CENSIG);
        put16(&mut central, version);
        put16(&mut central, version);
        put16(&mut central, flag);
        put16(&mut central, method);
        put32(&mut central, ENTRY_DOS_TIME);
        put32(&mut central, crc);
        put32(&mut central, compressed);
        put32(&mut central, size);
        put16(&mut central, name_length);
        put16(&mut central, 0); // extra
        put16(&mut central, 0); // comment
        put16(&mut central, 0); // disk
        put16(&mut central, 0); // internal attributes
        put32(&mut central, 0); // external attributes
        put32(&mut central, offset);
        central.extend_from_slice(name_bytes);
    }
    let central_offset = u32::try_from(out.len()).unwrap_or(u32::MAX);
    let central_length = u32::try_from(central.len()).unwrap_or(u32::MAX);
    let count = u16::try_from(entries.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&central);
    put32(&mut out, ENDSIG);
    put16(&mut out, 0);
    put16(&mut out, 0);
    put16(&mut out, count);
    put16(&mut out, count);
    put32(&mut out, central_length);
    put32(&mut out, central_offset);
    put16(&mut out, 0);
    Ok(out)
}

/// `ZipException("duplicate entry: …")`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("duplicate entry: {0}")]
pub struct DuplicateEntry(pub String);

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = Crc::new();
    crc.update(bytes);
    crc.sum()
}

/// `new Deflater(DEFAULT_COMPRESSION, true)` as `DeflaterOutputStream` drives it: the input handed over whole
/// without flushing, then finished.
fn deflate(bytes: &[u8]) -> Vec<u8> {
    let mut deflater = Compress::new(Compression::new(6), false);
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len().saturating_add(64));
    let mut rest = bytes;
    while !rest.is_empty() {
        out.reserve(4096);
        let before = deflater.total_in();
        if deflater.compress_vec(rest, &mut out, FlushCompress::None).is_err() {
            break;
        }
        let consumed = usize::try_from(deflater.total_in().saturating_sub(before)).unwrap_or(usize::MAX);
        rest = rest.get(consumed..).unwrap_or_default();
    }
    loop {
        out.reserve(4096);
        match deflater.compress_vec(&[], &mut out, FlushCompress::Finish) {
            Ok(Status::StreamEnd) | Err(_) => break,
            Ok(_) => {}
        }
    }
    out
}

fn put16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
