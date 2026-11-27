//! The platform an image is exported for, and the check that its archive holds it — `ImagePlatform` and
//! `ImageArchive`.
//!
//! **The save used to name no platform**, and the pull did. On a daemon with the containerd image store (Docker
//! Desktop, Docker Engine 29's default) a save without one wants the *host's* variant of a multi-architecture image:
//! on an arm64 host it failed (`content digest … not found`) while only the amd64 variant had been pulled, and
//! **exported the arm64 variant in silence** once both were — the inventory and the vulnerabilities of an
//! architecture nobody deploys, recorded as the image's.
//!
//! The save takes a `platform` since API 1.48, as a JSON-encoded OCI platform, and an older daemon ignores it; so
//! the archive is checked whatever the daemon: every configuration its `manifest.json` names must be of the platform
//! asked for, or the step fails (absent, decision 0007). Held to `reference/container/image-platform/`, which
//! `ImagePlatformReferenceSetTest` wrote — the archives there are the Java side's bytes, so the tar reader below is
//! held to it as much as the platform rules.

use serde_json::Value;
use std::io::{Read, Seek, SeekFrom};

/// What `manifest.json` may weigh; a daemon writes a few hundred bytes.
pub const MANIFEST_LIMIT: usize = 1024 * 1024;
/// What an image's configuration may weigh; a long history runs to tens of kilobytes.
pub const CONFIG_LIMIT: usize = 4 * 1024 * 1024;

const BLOCK: usize = 512;
/// What a GNU long name or a PAX header may hold.
const EXTENSION_LIMIT: u64 = 64 * 1024;
const NOT_A_TAR_ARCHIVE: &str = "it is not a tar archive";

/// One platform, normalized as containerd normalizes; an empty variant is "any" when asked, "none" when found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
    pub variant: String,
}

impl Platform {
    pub fn of(os: &str, architecture: &str, variant: &str) -> Platform {
        let mut os = os.to_ascii_lowercase();
        let mut architecture = architecture.to_ascii_lowercase();
        let mut variant = variant.to_ascii_lowercase();
        if os == "macos" {
            os = "darwin".to_owned();
        }
        match architecture.as_str() {
            "i386" => {
                architecture = "386".to_owned();
                variant.clear();
            }
            "x86_64" | "x86-64" | "amd64" => {
                architecture = "amd64".to_owned();
                if variant == "v1" {
                    variant.clear();
                }
            }
            "aarch64" | "arm64" => {
                architecture = "arm64".to_owned();
                if variant == "8" || variant == "v8" {
                    variant.clear();
                }
            }
            "armhf" => {
                architecture = "arm".to_owned();
                variant = "v7".to_owned();
            }
            "armel" => {
                architecture = "arm".to_owned();
                variant = "v6".to_owned();
            }
            "arm" => match variant.as_str() {
                "" | "7" => variant = "v7".to_owned(),
                "5" | "6" | "8" => variant = format!("v{variant}"),
                _ => {}
            },
            _ => {}
        }
        Platform { os, architecture, variant }
    }

    /// `os/architecture[/variant]`, a component nobody wrote shown as `unknown`.
    pub fn format(&self) -> String {
        let shown = |part: &str| if part.is_empty() { "unknown".to_owned() } else { part.to_owned() };
        let platform = format!("{}/{}", shown(&self.os), shown(&self.architecture));
        if self.variant.is_empty() { platform } else { format!("{platform}/{}", self.variant) }
    }

    /// The save's `platform` parameter. A requested platform's components are `[A-Za-z0-9_-]`, so nothing to escape.
    pub fn save_query(&self) -> String {
        let variant =
            if self.variant.is_empty() { String::new() } else { format!(",\"variant\":\"{}\"", self.variant) };
        format!("{{\"os\":\"{}\",\"architecture\":\"{}\"{variant}}}", self.os, self.architecture)
    }

    pub fn admits(&self, found: &Platform) -> bool {
        self.os == found.os
            && self.architecture == found.architecture
            && (self.variant.is_empty() || self.variant == found.variant)
    }
}

/// The platform `platform` asks for; `None` when it is blank — the task named none (Java's `null`), the daemon
/// chooses at the pull and at the save alike, and there is nothing to check against. `Err` is the step's sentence
/// when it is not `os/architecture[/variant]`.
pub fn requested(platform: &str) -> Result<Option<Platform>, String> {
    if vectispire_domain::java::is_blank(platform) {
        return Ok(None);
    }
    let parts: Vec<&str> = platform.split('/').collect();
    let well_formed = (2..=3).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
    match parts.as_slice() {
        [os, architecture] if well_formed => Ok(Some(Platform::of(os, architecture, ""))),
        [os, architecture, variant] if well_formed => Ok(Some(Platform::of(os, architecture, variant))),
        _ => Err(format!(
            "The image platform \"{platform}\" is not of the form os/architecture[/variant]; no image is exported for \
             a platform its archive cannot be checked against."
        )),
    }
}

/// Why the archive of `reference`, exported for `platform` (`asked` once parsed), may not be scanned — `None` when
/// every image it holds is of that platform. `entry` reads one file of the archive by name, bounded: `Ok(None)` when
/// the archive does not hold it, `Err` with why the archive cannot be read.
pub fn refusal(
    reference: &str,
    platform: &str,
    asked: &Platform,
    mut entry: impl FnMut(&str, usize) -> Result<Option<Vec<u8>>, String>,
) -> Option<String> {
    let found = match platforms(&mut entry) {
        Ok(found) => found,
        Err(why) => {
            return Some(format!(
                "The archive exported for {reference} could not be checked for {platform}: {why}. It is not scanned \
                 unchecked."
            ));
        }
    };
    if found.iter().all(|image| asked.admits(image)) {
        return None;
    }
    let found: Vec<String> = found.iter().map(Platform::format).collect();
    Some(format!(
        "The Docker daemon exported {reference} as {} where {platform} was asked: a daemon selects the platform of a \
         save from API 1.48 on, and another architecture is not scanned in place of the one asked for.",
        found.join(", ")
    ))
}

/// The platform of every image `manifest.json` lists, in its order.
fn platforms(entry: &mut impl FnMut(&str, usize) -> Result<Option<Vec<u8>>, String>) -> Result<Vec<Platform>, String> {
    let manifest = entry("manifest.json", MANIFEST_LIMIT)?.ok_or("it holds no manifest.json")?;
    let images = match json(&manifest) {
        Some(Value::Array(images)) if !images.is_empty() => images,
        _ => return Err("its manifest.json is not a list of images".to_owned()),
    };
    let mut configs = Vec::with_capacity(images.len());
    for image in &images {
        match image.get("Config").and_then(Value::as_str) {
            Some(config) if image.is_object() && !config.is_empty() => configs.push(config.to_owned()),
            _ => return Err("an image of its manifest.json names no configuration".to_owned()),
        }
    }
    let mut found = Vec::with_capacity(configs.len());
    for config in configs {
        let bytes = entry(&config, CONFIG_LIMIT)?.ok_or_else(|| format!("the configuration {config} is not in it"))?;
        let Some(document @ Value::Object(_)) = json(&bytes) else {
            return Err(format!("the configuration {config} is not a JSON object"));
        };
        let text = |field: &str| document.get(field).and_then(Value::as_str).unwrap_or_default().to_owned();
        found.push(Platform::of(&text("os"), &text("architecture"), &text("variant")));
    }
    Ok(found)
}

/// One JSON value and nothing after it, a leading byte-order mark skipped — Jackson's `readTree` with trailing
/// tokens refused.
fn json(bytes: &[u8]) -> Option<Value> {
    serde_json::from_slice(bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes)).ok()
}

// ------------------------------------------------------------------------------------------------ the tar

/// The bytes of the regular file `name` of the tar archive at `archive` (a leading `./` ignored on either side),
/// `None` when the archive does not hold it; `Err` with why when the archive is not one, or the entry is larger
/// than `limit`.
///
/// **Headers only, the layers skipped** — an archive runs to hundreds of megabytes and the files wanted are a few
/// kilobytes — and **the subset of tar a daemon writes**: POSIX ustar names with their prefix, GNU's long name entry,
/// a PAX header's `path` and `size`, base-256 sizes. A checksum that does not match, a size that is not a number or
/// an archive cut short is not a tar archive: a reader that guessed past it could find a configuration that is not
/// the image's. `ImageArchive`'s rules.
pub fn entry(archive: &std::path::Path, name: &str, limit: usize) -> Result<Option<Vec<u8>>, String> {
    let file = std::fs::File::open(archive).map_err(unreadable)?;
    entry_of(std::io::BufReader::new(file), name, limit)
}

/// [`entry`], from any seekable reader.
pub fn entry_of(mut input: impl Read + Seek, name: &str, limit: usize) -> Result<Option<Vec<u8>>, String> {
    let wanted = without_dot_slash(name);
    let end = input.seek(SeekFrom::End(0)).map_err(unreadable)?;
    input.seek(SeekFrom::Start(0)).map_err(unreadable)?;
    let mut pending_name: Option<String> = None;
    let mut pending_size: Option<u64> = None;
    let mut header = [0u8; BLOCK];
    loop {
        match read_full(&mut input, &mut header)? {
            0 => return Ok(None),
            BLOCK => {}
            _ => return Err(not_a_tar()),
        }
        if header.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        if checksum(&header) != number(field(&header, 148, 8))? {
            return Err(not_a_tar());
        }
        let size = number(field(&header, 124, 12))?;
        let kind = header.get(156).copied().unwrap_or_default();
        match kind {
            b'L' => {
                pending_name = Some(c_string(&extension(&mut input, size, end)?));
                continue;
            }
            b'x' => {
                let (path, pax_size) = pax(&extension(&mut input, size, end)?)?;
                if path.is_some() {
                    pending_name = path;
                }
                if pax_size.is_some() {
                    pending_size = pax_size;
                }
                continue;
            }
            _ => {}
        }
        let entry_name = pending_name.take().unwrap_or_else(|| header_name(&header));
        let entry_size = pending_size.take().unwrap_or(size);
        let regular = kind == b'0' || kind == 0;
        if regular && without_dot_slash(&entry_name) == wanted {
            if entry_size > limit as u64 {
                return Err(format!("{wanted} is larger than {limit} bytes"));
            }
            return read_exactly(&mut input, entry_size).map(Some);
        }
        skip(&mut input, padded(entry_size)?, end)?;
    }
}

fn not_a_tar() -> String {
    NOT_A_TAR_ARCHIVE.to_owned()
}

fn unreadable(error: std::io::Error) -> String {
    format!("it could not be read: {error}")
}

/// `length` bytes of `header` from `offset`; none when out of bounds, which no caller asks.
fn field(header: &[u8], offset: usize, length: usize) -> &[u8] {
    header.get(offset..offset.saturating_add(length)).unwrap_or_default()
}

/// Reads until `block` is full or the input ends; how many bytes it got.
fn read_full(input: &mut impl Read, block: &mut [u8]) -> Result<usize, String> {
    let mut filled = 0usize;
    loop {
        let Some(rest) = block.get_mut(filled..) else { return Ok(filled) };
        if rest.is_empty() {
            return Ok(filled);
        }
        match input.read(rest) {
            Ok(0) => return Ok(filled),
            Ok(read) => filled = filled.saturating_add(read),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(unreadable(error)),
        }
    }
}

/// Exactly `size` bytes, or not a tar archive.
fn read_exactly(input: &mut impl Read, size: u64) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    input.take(size).read_to_end(&mut data).map_err(unreadable)?;
    if (data.len() as u64) < size { Err(not_a_tar()) } else { Ok(data) }
}

/// A GNU long name's or a PAX header's data, padding consumed.
fn extension(input: &mut (impl Read + Seek), size: u64, end: u64) -> Result<Vec<u8>, String> {
    if size > EXTENSION_LIMIT {
        return Err(not_a_tar());
    }
    let data = read_exactly(input, size)?;
    skip(input, padded(size)?.saturating_sub(size), end)?;
    Ok(data)
}

/// `"<length> <key>=<value>\n"` records, the length counting the whole record: the `path` and the `size`.
fn pax(records: &[u8]) -> Result<(Option<String>, Option<u64>), String> {
    let (mut path, mut size) = (None, None);
    let mut rest = records;
    while !rest.is_empty() {
        let space = rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
        let (digits, _) = rest.split_at_checked(space).ok_or_else(not_a_tar)?;
        let length = usize::try_from(decimal(digits)?).map_err(|_| not_a_tar())?;
        // At least the digits, the space and the newline; within what is left; ending the record with its newline.
        let (record, after) = rest.split_at_checked(length).ok_or_else(not_a_tar)?;
        let body = record
            .strip_suffix(b"\n")
            .and_then(|record| record.get(space.saturating_add(1)..))
            .filter(|_| length > space)
            .ok_or_else(not_a_tar)?;
        let equals = body.iter().position(|&b| b == b'=').ok_or_else(not_a_tar)?;
        let (key, value) = body.split_at_checked(equals).ok_or_else(not_a_tar)?;
        let value = value.get(1..).unwrap_or_default();
        match key {
            b"path" => path = Some(String::from_utf8_lossy(value).into_owned()),
            b"size" => size = Some(decimal(String::from_utf8_lossy(value).as_bytes())?),
            _ => {}
        }
        rest = after;
    }
    Ok((path, size))
}

/// A non-empty run of ASCII digits, at most eighteen of them.
fn decimal(digits: &[u8]) -> Result<u64, String> {
    if digits.is_empty() || digits.len() > 18 {
        return Err(not_a_tar());
    }
    digits.iter().try_fold(0u64, |value, &digit| {
        let digit = char::from(digit).to_digit(10).ok_or_else(not_a_tar)?;
        value.checked_mul(10).and_then(|value| value.checked_add(u64::from(digit))).ok_or_else(not_a_tar)
    })
}

/// A numeric field: octal digits between optional spaces and NULs, or base-256 when its first byte has the high
/// bit — a size of 8 GiB or more. A negative or overflowing number is not a size.
pub fn number(field: &[u8]) -> Result<u64, String> {
    let (&first, rest) = field.split_first().ok_or_else(not_a_tar)?;
    if first & 0x80 != 0 {
        if first & 0x40 != 0 {
            return Err(not_a_tar());
        }
        return rest.iter().try_fold(u64::from(first & 0x3f), |value, &byte| {
            // Java's `long`: what does not fit in 63 bits is not a size.
            if value > (u64::MAX >> 9) {
                return Err(not_a_tar());
            }
            Ok((value << 8) | u64::from(byte))
        });
    }
    let padding = |b: &u8| *b == b' ' || *b == 0;
    let start = field.iter().position(|b| !padding(b)).unwrap_or(field.len());
    let end = field.iter().rposition(|b| !padding(b)).map_or(start, |last| last.saturating_add(1));
    field.get(start..end).ok_or_else(not_a_tar)?.iter().try_fold(0u64, |value, &digit| {
        let digit = char::from(digit).to_digit(8).ok_or_else(not_a_tar)?;
        value.checked_mul(8).and_then(|value| value.checked_add(u64::from(digit))).ok_or_else(not_a_tar)
    })
}

/// The sum of the header's unsigned bytes, its own checksum field counted as spaces.
fn checksum(header: &[u8; BLOCK]) -> u64 {
    header
        .iter()
        .enumerate()
        .map(|(at, &byte)| if (148..156).contains(&at) { u64::from(b' ') } else { u64::from(byte) })
        .sum()
}

/// The name, behind its ustar prefix when the header is POSIX's (GNU's uses those bytes otherwise).
fn header_name(header: &[u8; BLOCK]) -> String {
    let name = c_string(field(header, 0, 100));
    if field(header, 257, 6) == b"ustar\0" {
        let prefix = c_string(field(header, 345, 155));
        if !prefix.is_empty() {
            return format!("{prefix}/{name}");
        }
    }
    name
}

fn c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(bytes.get(..end).unwrap_or_default()).into_owned()
}

fn without_dot_slash(name: &str) -> &str {
    name.strip_prefix("./").unwrap_or(name)
}

/// `size` rounded up to whole blocks.
fn padded(size: u64) -> Result<u64, String> {
    size.div_ceil(BLOCK as u64).checked_mul(BLOCK as u64).ok_or_else(not_a_tar)
}

/// Past `count` bytes, by seeking — or not a tar archive, when they run past its `end`.
fn skip(input: &mut impl Seek, count: u64, end: u64) -> Result<(), String> {
    let here = input.stream_position().map_err(unreadable)?;
    match here.checked_add(count) {
        Some(there) if there <= end => input.seek(SeekFrom::Start(there)).map(|_| ()).map_err(unreadable),
        _ => Err(not_a_tar()),
    }
}
