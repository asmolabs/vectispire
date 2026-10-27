//! The part of an X.509 certificate a pinned CA is judged on, read as BouncyCastle 1.86 reads it for
//! `PinnedCa`: the structure `X509CertificateHolder` accepts, the subject as `X500Name.toString` renders it
//! (`BCStyle`), the basic constraints, the key usage and the validity.
//!
//! **A reader of its own, not a crate's.** The workspace's `der` has no tag for UniversalString, GraphicString or
//! GeneralString, and its OIDs refuse an encoding under three bytes; each appears in names BouncyCastle renders,
//! and a refusal here where Java renders would be a CA one side pins and the other does not. What the reader
//! needs is small: a tag, a definite length, the value. It is written without indexing or unchecked arithmetic,
//! on bytes a stranger may have pasted, and fuzzed (`fuzz/fuzz_targets/collector_ca.rs`).
//!
//! **Stricter than BouncyCastle, never looser**, where the two differ (each is a certificate Java pins and this
//! refuses as unreadable — never the other way round): a BER length (indefinite, or not in its shortest form), a
//! constructed string, a tag number above 30, a time outside the DER forms (`YYMMDDHHMMSSZ`, `YYYYMMDDHHMMSSZ`) or
//! naming a date that does not exist, an object identifier arc beyond 128 bits, a version tagged other than `[0]`.

use crate::instant::Instant;

/// One element: its identifier octet, its contents, and its whole encoding.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    pub encoded: &'a [u8],
}

pub(crate) const BOOLEAN: u8 = 0x01;
pub(crate) const INTEGER: u8 = 0x02;
pub(crate) const BIT_STRING: u8 = 0x03;
pub(crate) const OCTET_STRING: u8 = 0x04;
pub(crate) const OID: u8 = 0x06;
pub(crate) const UTF8_STRING: u8 = 0x0c;
pub(crate) const UTC_TIME: u8 = 0x17;
pub(crate) const GENERALIZED_TIME: u8 = 0x18;
pub(crate) const BMP_STRING: u8 = 0x1e;
pub(crate) const SEQUENCE: u8 = 0x30;
pub(crate) const SET: u8 = 0x31;
/// `[0]`, `[1]`, `[2]`, `[3]` constructed, and `[1]`, `[2]` primitive (the unique identifiers).
const CONTEXT: u8 = 0x80;
const CONSTRUCTED: u8 = 0x20;

/// The basic constraints' and the key usage's identifiers, as encoded (`2.5.29.19`, `2.5.29.15`).
const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];

/// Reads one element off the front of `input`.
pub(crate) fn read(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        // More than four octets of length is more than any CA. BER's indefinite length (0x80, no octet) falls to
        // the shortest-form check below, as a length of zero.
        if count > 4 {
            return None;
        }
        let (octets, rest) = rest.split_at_checked(count)?;
        if octets.first() == Some(&0) {
            return None;
        }
        let length = octets
            .iter()
            .try_fold(0usize, |length, octet| length.checked_mul(256)?.checked_add(usize::from(*octet)))?;
        if length < 0x80 {
            return None;
        }
        (length, rest)
    };
    let (value, rest) = rest.split_at_checked(length)?;
    let (encoded, _) = input.split_at_checked(input.len().checked_sub(rest.len())?)?;
    Some((Tlv { tag, value, encoded }, rest))
}

/// Exactly one element, nothing after it — `ASN1Primitive.fromByteArray`, which refuses trailing data.
pub(crate) fn read_whole(input: &[u8]) -> Option<Tlv<'_>> {
    let (element, rest) = read(input)?;
    rest.is_empty().then_some(element)
}

/// The elements of a constructed value, in order.
pub(crate) fn elements(value: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let mut items = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let (item, after) = read(rest)?;
        items.push(item);
        rest = after;
    }
    Some(items)
}

fn expect(element: Option<&Tlv<'_>>, tag: u8) -> Option<()> {
    (element?.tag == tag).then_some(())
}

/// `ASN1Integer`'s check: not empty, and not a redundant leading octet.
fn integer(element: Option<&Tlv<'_>>) -> Option<()> {
    let element = element.filter(|element| element.tag == INTEGER)?;
    let mut octets = element.value.iter();
    let first = *octets.next()?;
    match octets.next() {
        Some(second) if (first == 0 && second & 0x80 == 0) || (first == 0xff && second & 0x80 != 0) => None,
        _ => Some(()),
    }
}

/// `ASN1Boolean`: one octet, true unless zero.
fn boolean(element: &Tlv<'_>) -> Option<bool> {
    if element.tag != BOOLEAN {
        return None;
    }
    match element.value {
        [octet] => Some(*octet != 0),
        _ => None,
    }
}

/// `ASN1BitString`: the unused-bit count first, at most 7, and none when there is no bit.
fn bit_string<'a>(element: &Tlv<'a>) -> Option<(u8, &'a [u8])> {
    if element.tag != BIT_STRING {
        return None;
    }
    let (&unused, bits) = element.value.split_first()?;
    (unused <= 7 && (unused == 0 || !bits.is_empty())).then_some((unused, bits))
}

/// An object identifier's arcs, dotted, as `ASN1ObjectIdentifier.getId` writes it — `None` for an encoding it
/// refuses (empty, an arc in more octets than it needs, the last octet continuing).
pub(crate) fn oid(element: &Tlv<'_>) -> Option<String> {
    if element.tag != OID || element.value.is_empty() || element.value.last().is_some_and(|last| last & 0x80 != 0) {
        return None;
    }
    let mut arcs: Vec<String> = Vec::new();
    let mut arc: u128 = 0;
    let mut starting = true;
    for octet in element.value {
        if starting && *octet == 0x80 {
            return None;
        }
        arc = arc.checked_mul(128)?.checked_add(u128::from(octet & 0x7f))?;
        starting = octet & 0x80 == 0;
        if starting {
            if arcs.is_empty() {
                let (first, second) = match arc {
                    0..40 => (0, arc),
                    40..80 => (1, arc.checked_sub(40)?),
                    _ => (2, arc.checked_sub(80)?),
                };
                arcs.push(first.to_string());
                arcs.push(second.to_string());
            } else {
                arcs.push(arc.to_string());
            }
            arc = 0;
        }
    }
    Some(arcs.join("."))
}

/// `AlgorithmIdentifier`: an identifier and, perhaps, its parameters.
fn algorithm(element: Option<&Tlv<'_>>) -> Option<()> {
    let element = element.filter(|element| element.tag == SEQUENCE)?;
    let items = elements(element.value)?;
    if items.is_empty() || items.len() > 2 {
        return None;
    }
    oid(items.first()?).map(|_| ())
}

/// A `Name` as `X500Name.getInstance` takes it: a sequence of sets, their contents read only when rendered.
fn name<'a>(element: Option<&Tlv<'a>>) -> Option<Vec<Tlv<'a>>> {
    let element = element.filter(|element| element.tag == SEQUENCE)?;
    let rdns = elements(element.value)?;
    rdns.iter().all(|rdn| rdn.tag == SET).then_some(rdns)
}

/// A certificate as `PinnedCa` reads it.
#[derive(Debug, Clone)]
pub(crate) struct Certificate<'a> {
    pub encoded: &'a [u8],
    subject: Vec<Tlv<'a>>,
    not_before: Tlv<'a>,
    not_after: Tlv<'a>,
    extensions: Vec<(&'a [u8], &'a [u8])>,
}

impl<'a> Certificate<'a> {
    /// `new X509CertificateHolder(der)`: the structure, each check `TBSCertificate` and `Extensions` make.
    pub fn parse(der: &'a [u8]) -> Option<Certificate<'a>> {
        let certificate = read_whole(der).filter(|certificate| certificate.tag == SEQUENCE)?;
        let parts = elements(certificate.value)?;
        let [tbs, signature_algorithm, signature] = parts.as_slice() else { return None };
        algorithm(Some(signature_algorithm))?;
        bit_string(signature)?;
        let tbs = Some(tbs).filter(|tbs| tbs.tag == SEQUENCE)?;
        let fields = elements(tbs.value)?;
        let mut fields = fields.iter().peekable();

        // No `[0]` is a version 1 certificate; BouncyCastle reads the tag as explicit.
        let version = match fields.peek() {
            Some(field) if field.tag == CONTEXT | CONSTRUCTED => {
                let tagged = read_whole(field.value)?;
                integer(Some(&tagged))?;
                fields.next();
                match tagged.value {
                    [0] => 1,
                    [1] => 2,
                    [2] => 3,
                    _ => return None,
                }
            }
            Some(field) if field.tag & CONTEXT != 0 => return None,
            _ => 1,
        };
        integer(fields.next())?;
        algorithm(fields.next())?;
        // RFC 5280: an issuer is never an empty name; BouncyCastle refuses one unless told otherwise.
        if name(fields.next())?.is_empty() {
            return None;
        }
        let validity = fields.next().filter(|validity| validity.tag == SEQUENCE)?;
        let times = elements(validity.value)?;
        let [not_before, not_after] = times.as_slice() else { return None };
        for time in [not_before, not_after] {
            if time.tag != UTC_TIME && time.tag != GENERALIZED_TIME {
                return None;
            }
        }
        let subject = name(fields.next())?;
        let key = fields.next().filter(|key| key.tag == SEQUENCE)?;
        let key_parts = elements(key.value)?;
        let [key_algorithm, key_bits] = key_parts.as_slice() else { return None };
        algorithm(Some(key_algorithm))?;
        bit_string(key_bits)?;

        // The extras, read last to first as BouncyCastle reads them: the first `[3]` is the one that stays.
        let extras: Vec<&Tlv<'a>> = fields.collect();
        if version == 1 && !extras.is_empty() {
            return None;
        }
        let mut extensions = Vec::new();
        for extra in extras.iter().rev() {
            match extra.tag {
                // The unique identifiers: implicitly tagged bit strings.
                0x81 | 0x82 => {
                    bit_string(&Tlv { tag: BIT_STRING, ..**extra })?;
                }
                0xa3 if version != 2 => extensions = read_extensions(extra.value)?,
                _ => return None,
            }
        }
        Some(Certificate {
            encoded: certificate.encoded,
            subject,
            not_before: *not_before,
            not_after: *not_after,
            extensions,
        })
    }

    /// `X500Name.toString` under `BCStyle`; `None` where rendering throws.
    pub fn subject(&self) -> Option<String> {
        let mut rendered = Vec::with_capacity(self.subject.len());
        for rdn in &self.subject {
            let values = elements(rdn.value)?;
            // Every value of a multi-valued RDN, joined by `+`; a single-valued one is its first and only value,
            // and an empty set renders as nothing.
            let read = values.as_slice();
            let mut parts = Vec::with_capacity(read.len());
            for value in read {
                parts.push(type_and_value(value)?);
            }
            rendered.push(parts.join("+"));
        }
        Some(rendered.join(","))
    }

    /// `BasicConstraints.fromExtensions(…).isCA()`: `None` when the extension is there and unreadable.
    pub fn is_ca(&self) -> Option<bool> {
        let Some(value) = self.extension(BASIC_CONSTRAINTS) else { return Some(false) };
        let constraints = read_whole(value).filter(|constraints| constraints.tag == SEQUENCE)?;
        let items = elements(constraints.value)?;
        let mut items = items.iter();
        let Some(first) = items.next() else { return Some(false) };
        if first.tag == BOOLEAN {
            let ca = boolean(first)?;
            if let Some(path_length) = items.next() {
                integer(Some(path_length))?;
            }
            Some(ca)
        } else {
            integer(Some(first))?;
            // A path length with no CA flag before it, and something after it: "wrong sequence in constructor".
            if items.next().is_some() {
                return None;
            }
            Some(false)
        }
    }

    /// `KeyUsage.fromExtensions(…)`: `Some(None)` when there is none, `Some(Some(may sign))` when there is one —
    /// asked as `ASN1BitString.intValue() & keyCertSign`, whose last octet has its unused bits masked off.
    pub fn may_sign_certificates(&self) -> Option<Option<bool>> {
        let Some(value) = self.extension(KEY_USAGE) else { return Some(None) };
        let (unused, bits) = bit_string(&read_whole(value)?)?;
        let may = match bits {
            [] => false,
            // keyCertSign is bit 5, 0x04 of the first octet; as the last octet, its unused bits are masked.
            [only] => only & 0x04 != 0 && unused <= 2,
            [first, ..] => first & 0x04 != 0,
        };
        Some(Some(may))
    }

    pub fn not_before(&self) -> Option<Instant> {
        time(&self.not_before)
    }

    pub fn not_after(&self) -> Option<Instant> {
        time(&self.not_after)
    }

    fn extension(&self, id: &[u8]) -> Option<&'a [u8]> {
        self.extensions.iter().find(|(extension, _)| *extension == id).map(|(_, value)| *value)
    }
}

/// `Extensions`: each one an identifier, perhaps a criticality, an octet string — and none twice.
fn read_extensions(explicit: &[u8]) -> Option<Vec<(&[u8], &[u8])>> {
    let sequence = read_whole(explicit).filter(|sequence| sequence.tag == SEQUENCE)?;
    let mut read: Vec<(&[u8], &[u8])> = Vec::new();
    for extension in elements(sequence.value)? {
        if extension.tag != SEQUENCE {
            return None;
        }
        let parts = elements(extension.value)?;
        let (id, value) = match parts.as_slice() {
            [id, value] => (id, value),
            [id, critical, value] => {
                boolean(critical)?;
                (id, value)
            }
            _ => return None,
        };
        oid(id)?;
        expect(Some(value), OCTET_STRING)?;
        if read.iter().any(|(known, _)| *known == id.value) {
            return None;
        }
        read.push((id.value, value.value));
    }
    Some(read)
}

/// The types `BCStyle` names; any other is written as its dotted identifier.
const SYMBOLS: &[(&str, &str)] = &[
    ("0.9.2342.19200300.100.1.1", "UID"),
    ("0.9.2342.19200300.100.1.25", "DC"),
    ("1.2.840.113549.1.9.1", "E"),
    ("1.2.840.113549.1.9.2", "unstructuredName"),
    ("1.2.840.113549.1.9.8", "unstructuredAddress"),
    ("1.3.36.8.3.14", "NameAtBirth"),
    ("1.3.6.1.4.1.311.60.2.1.1", "jurisdictionLocality"),
    ("1.3.6.1.4.1.311.60.2.1.2", "jurisdictionState"),
    ("1.3.6.1.4.1.311.60.2.1.3", "jurisdictionCountry"),
    ("1.3.6.1.5.5.7.9.1", "DateOfBirth"),
    ("1.3.6.1.5.5.7.9.2", "PlaceOfBirth"),
    ("1.3.6.1.5.5.7.9.3", "Gender"),
    ("1.3.6.1.5.5.7.9.4", "CountryOfCitizenship"),
    ("1.3.6.1.5.5.7.9.5", "CountryOfResidence"),
    ("2.5.4.10", "O"),
    ("2.5.4.11", "OU"),
    ("2.5.4.12", "T"),
    ("2.5.4.13", "DESCRIPTION"),
    ("2.5.4.15", "BusinessCategory"),
    ("2.5.4.16", "PostalAddress"),
    ("2.5.4.17", "PostalCode"),
    ("2.5.4.20", "TelephoneNumber"),
    ("2.5.4.3", "CN"),
    ("2.5.4.4", "SURNAME"),
    ("2.5.4.41", "Name"),
    ("2.5.4.42", "GIVENNAME"),
    ("2.5.4.43", "INITIALS"),
    ("2.5.4.44", "GENERATION"),
    ("2.5.4.45", "UniqueIdentifier"),
    ("2.5.4.46", "DN"),
    ("2.5.4.5", "SERIALNUMBER"),
    ("2.5.4.6", "C"),
    ("2.5.4.65", "Pseudonym"),
    ("2.5.4.7", "L"),
    ("2.5.4.72", "ROLE"),
    ("2.5.4.8", "ST"),
    ("2.5.4.9", "STREET"),
    ("2.5.4.97", "organizationIdentifier"),
];

/// `IETFUtils.appendTypeAndValue`: `AttributeTypeAndValue` is a sequence whose first element is the type and
/// second the value; BouncyCastle ignores anything after them.
fn type_and_value(element: &Tlv<'_>) -> Option<String> {
    if element.tag != SEQUENCE {
        return None;
    }
    let parts = elements(element.value)?;
    let mut parts = parts.iter();
    let id = oid(parts.next()?)?;
    let value = parts.next()?;
    let symbol = SYMBOLS.iter().find(|(known, _)| *known == id).map_or(id.as_str(), |(_, symbol)| symbol);
    Some(format!("{symbol}={}", value_to_string(value)?))
}

/// `IETFUtils.valueToString`: a string as text, anything else as `#` and its encoding in hex; then the RFC 4514
/// specials escaped, and leading and trailing spaces — leading ones only without a `\#` prefix.
fn value_to_string(value: &Tlv<'_>) -> Option<String> {
    let text = match value.tag {
        // Each octet one character, as `Strings.fromByteArray` reads them: Numeric, Printable, Teletex,
        // Videotex, IA5, Graphic, Visible, General.
        0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x19 | 0x1a | 0x1b => {
            let text: String = value.value.iter().map(|octet| char::from(*octet)).collect();
            hash_escaped(text)
        }
        UTF8_STRING => hash_escaped(std::str::from_utf8(value.value).ok()?.to_owned()),
        // UTF-16 units, a lone surrogate written `?` as Java writes it out.
        BMP_STRING => {
            let (pairs, odd) = value.value.as_chunks::<2>();
            if !odd.is_empty() {
                return None;
            }
            let units: Vec<u16> = pairs.iter().map(|pair| u16::from_be_bytes(*pair)).collect();
            hash_escaped(crate::java::from_utf16(&units))
        }
        // `ASN1BitString.getString`: `#` and its encoding in upper-case hex, which then starts with `#`.
        BIT_STRING => {
            bit_string(value)?;
            format!("\\#{}", hex(value.encoded, true))
        }
        // UniversalString (0x1c) is excluded from the strings, and every other value is its encoding.
        _ => format!("#{}", hex(value.encoded, false)),
    };
    Some(escape(&text))
}

/// A string value starting with `#` is written `\#`, so that it does not read as an encoding.
fn hash_escaped(text: String) -> String {
    if text.starts_with('#') { format!("\\{text}") } else { text }
}

fn hex(bytes: &[u8], upper: bool) -> String {
    bytes.iter().map(|byte| if upper { format!("{byte:02X}") } else { format!("{byte:02x}") }).collect()
}

/// The single pass of `valueToString`: `,"\+=<>;` escaped everywhere after a `\#` prefix, a space escaped when
/// it leads (without that prefix) or trails.
fn escape(text: &str) -> String {
    let (prefix, body) = match text.strip_prefix("\\#") {
        Some(body) => ("\\#", body),
        None => ("", text),
    };
    let chars: Vec<char> = text.chars().collect();
    let leading = chars.iter().take_while(|c| **c == ' ').count();
    let trailing_from = chars.len().saturating_sub(chars.iter().rev().take_while(|c| **c == ' ').count());
    let mut out = String::with_capacity(text.len());
    out.push_str(prefix);
    let skip = prefix.chars().count();
    for (position, c) in body.chars().enumerate() {
        let index = position.saturating_add(skip);
        let escaped = match c {
            ',' | '"' | '\\' | '+' | '=' | '<' | '>' | ';' => true,
            // With a `\#` prefix the text starts with a backslash, so `leading` is zero: no leading space there.
            ' ' => index < leading || index >= trailing_from,
            _ => false,
        };
        if escaped {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A validity time in its DER form: `YYMMDDHHMMSSZ` (years 1950 to 2049, as BouncyCastle pivots them) or
/// `YYYYMMDDHHMMSSZ`.
fn time(element: &Tlv<'_>) -> Option<Instant> {
    let (zone, digits) = element.value.split_last()?;
    if *zone != b'Z' || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let number = |digits: &[u8]| {
        digits
            .iter()
            .try_fold(0u32, |value, digit| value.checked_mul(10)?.checked_add(u32::from(digit.checked_sub(b'0')?)))
    };
    let (year, rest) = match (element.tag, digits.len()) {
        (UTC_TIME, 12) => {
            let (year, rest) = digits.split_at_checked(2)?;
            let year = number(year)?;
            (i64::from(if year < 50 { year.checked_add(2000)? } else { year.checked_add(1900)? }), rest)
        }
        (GENERALIZED_TIME, 14) => {
            let (year, rest) = digits.split_at_checked(4)?;
            (i64::from(number(year)?), rest)
        }
        _ => return None,
    };
    let (pairs, _) = rest.as_chunks::<2>();
    let [month, day, hour, minute, second] = pairs else { return None };
    Instant::of_utc(year, number(month)?, number(day)?, number(hour)?, number(minute)?, number(second)?)
}

#[cfg(test)]
mod tests {
    //! The structural refusals BouncyCastle's builder cannot be made to write, on certificates assembled here: the
    //! signature is never verified by a pinned CA's reading, so any bytes stand in for it.

    use super::*;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            length @ 0..0x80 => out.push(u8::try_from(length).unwrap()),
            length @ 0x80..0x100 => out.extend([0x81, u8::try_from(length).unwrap()]),
            length => out.extend([0x82, u8::try_from(length >> 8).unwrap(), u8::try_from(length & 0xff).unwrap()]),
        }
        out.extend_from_slice(content);
        out
    }

    fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(SEQUENCE, &parts.concat())
    }

    fn name(common_name: &str) -> Vec<u8> {
        let atv = seq(&[tlv(OID, &[0x55, 0x04, 0x03]), tlv(UTF8_STRING, common_name.as_bytes())]);
        seq(&[tlv(SET, &atv)])
    }

    fn extension(id: &[u8], value: Vec<u8>) -> Vec<u8> {
        seq(&[tlv(OID, id), tlv(BOOLEAN, &[0xff]), tlv(OCTET_STRING, &value)])
    }

    fn ca_extensions() -> Vec<Vec<u8>> {
        vec![extension(BASIC_CONSTRAINTS, seq(&[tlv(BOOLEAN, &[0xff])]))]
    }

    /// A certificate of `version` (`None`: no `[0]`), with these extensions (`None`: no `[3]`) and extras.
    fn certificate(
        version: Option<u8>,
        issuer: Vec<u8>,
        extensions: Option<Vec<Vec<u8>>>,
        extras: &[Vec<u8>],
    ) -> Vec<u8> {
        let algorithm = seq(&[tlv(OID, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])]);
        let mut fields = Vec::new();
        if let Some(version) = version {
            fields.push(tlv(0xa0, &tlv(INTEGER, &[version])));
        }
        fields.push(tlv(INTEGER, &[0x01]));
        fields.push(algorithm.clone());
        fields.push(issuer);
        fields.push(seq(&[tlv(UTC_TIME, b"260101000000Z"), tlv(UTC_TIME, b"360101000000Z")]));
        fields.push(name("Built"));
        fields.push(seq(&[
            seq(&[tlv(OID, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])]),
            tlv(BIT_STRING, &[0x00, 0x04]),
        ]));
        fields.extend_from_slice(extras);
        if let Some(extensions) = extensions {
            fields.push(tlv(0xa3, &seq(&extensions)));
        }
        seq(&[seq(&fields), algorithm, tlv(BIT_STRING, &[0x00, 0x01])])
    }

    #[test]
    fn a_well_formed_v3_ca_is_read() {
        let der = certificate(Some(2), name("Issuer"), Some(ca_extensions()), &[]);
        let read = Certificate::parse(&der).unwrap();
        assert_eq!(read.subject().as_deref(), Some("CN=Built"));
        assert_eq!(read.is_ca(), Some(true));
        assert_eq!(read.may_sign_certificates(), Some(None));
        assert_eq!(read.not_after().and_then(Instant::to_java_string).as_deref(), Some("2036-01-01T00:00:00Z"));
        // The unique identifiers are allowed before the extensions.
        let with_ids = certificate(Some(2), name("Issuer"), Some(ca_extensions()), &[tlv(0x81, &[0x00, 0x01])]);
        assert!(Certificate::parse(&with_ids).is_some());
    }

    #[test]
    fn the_structural_refusals_of_tbs_certificate() {
        // "version 1 certificate contains extra data".
        assert!(Certificate::parse(&certificate(None, name("Issuer"), Some(ca_extensions()), &[])).is_none());
        assert!(Certificate::parse(&certificate(None, name("Issuer"), None, &[])).is_some());
        // "version 2 certificate cannot contain extensions".
        assert!(Certificate::parse(&certificate(Some(1), name("Issuer"), Some(ca_extensions()), &[])).is_none());
        assert!(Certificate::parse(&certificate(Some(1), name("Issuer"), None, &[])).is_some());
        // "version number not recognised".
        assert!(Certificate::parse(&certificate(Some(3), name("Issuer"), Some(ca_extensions()), &[])).is_none());
        // "certificate issuer is an empty distinguished name".
        assert!(Certificate::parse(&certificate(Some(2), seq(&[]), Some(ca_extensions()), &[])).is_none());
        // "Unknown tag encountered in structure".
        assert!(Certificate::parse(&certificate(Some(2), name("Issuer"), None, &[tlv(0xa4, &[])])).is_none());
    }

    #[test]
    fn an_extension_given_twice_is_refused() {
        let twice = vec![ca_extensions().remove(0), ca_extensions().remove(0)];
        assert!(Certificate::parse(&certificate(Some(2), name("Issuer"), Some(twice), &[])).is_none());
        // An empty extension block is not an error: "quite a few" are out there.
        assert!(Certificate::parse(&certificate(Some(2), name("Issuer"), Some(Vec::new()), &[])).is_some());
    }

    #[test]
    fn basic_constraints_read_as_bouncy_castle_reads_them() {
        let read = |constraints: Vec<u8>| {
            let der = certificate(Some(2), name("I"), Some(vec![extension(BASIC_CONSTRAINTS, constraints)]), &[]);
            Certificate::parse(&der).unwrap().is_ca()
        };
        assert_eq!(read(seq(&[])), Some(false));
        assert_eq!(read(seq(&[tlv(BOOLEAN, &[0x00])])), Some(false));
        assert_eq!(read(seq(&[tlv(BOOLEAN, &[0x01])])), Some(true), "any non-zero octet is true");
        assert_eq!(read(seq(&[tlv(BOOLEAN, &[0xff]), tlv(INTEGER, &[0x00])])), Some(true));
        // A path length alone is no CA; a path length followed by anything is "wrong sequence in constructor".
        assert_eq!(read(seq(&[tlv(INTEGER, &[0x00])])), Some(false));
        assert_eq!(read(seq(&[tlv(INTEGER, &[0x00]), tlv(BOOLEAN, &[0xff])])), None);
        // A redundant leading octet makes the integer malformed.
        assert_eq!(read(seq(&[tlv(BOOLEAN, &[0xff]), tlv(INTEGER, &[0x00, 0x01])])), None);
        assert_eq!(read(tlv(OCTET_STRING, &[])), None, "not a sequence");
    }

    #[test]
    fn key_usage_is_asked_as_int_value_asks_it() {
        let may = |bits: &[u8]| {
            let usage = extension(KEY_USAGE, tlv(BIT_STRING, bits));
            let der = certificate(Some(2), name("I"), Some(vec![ca_extensions().remove(0), usage]), &[]);
            Certificate::parse(&der).unwrap().may_sign_certificates()
        };
        assert_eq!(may(&[0x02, 0x04]), Some(Some(true)));
        // The only octet is also the last: its unused bits are masked off before keyCertSign is asked.
        assert_eq!(may(&[0x03, 0x04]), Some(Some(false)));
        assert_eq!(may(&[0x07, 0x04, 0x80]), Some(Some(true)), "not the last octet: not masked");
        assert_eq!(may(&[0x00]), Some(Some(false)));
        assert_eq!(may(&[0x08, 0x04]), None, "more than seven unused bits");
    }

    #[test]
    fn ber_lengths_and_high_tag_numbers_are_refused() {
        assert!(read(&[0x30, 0x80, 0x00, 0x00]).is_none(), "indefinite");
        assert!(read(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]).is_none(), "long form for a short length");
        assert!(read(&[0x04, 0x82, 0x00, 0x80]).is_none(), "a leading zero octet of length");
        assert!(read(&[0x1f, 0x22, 0x00]).is_none(), "a high tag number");
        assert!(read(&[0x04, 0x05, 1, 2]).is_none(), "shorter than it says");
        assert_eq!(
            read(&[0x04, 0x01, 7, 9]).map(|(element, rest)| (element.value, rest)),
            Some((&[7u8][..], &[9u8][..]))
        );
    }

    #[test]
    fn object_identifiers_are_written_as_get_id_writes_them() {
        let id = |bytes: &[u8]| oid(&Tlv { tag: OID, value: bytes, encoded: bytes });
        assert_eq!(id(&[0x55, 0x04, 0x03]).as_deref(), Some("2.5.4.3"));
        assert_eq!(id(&[0x55]).as_deref(), Some("2.5"), "shorter than three octets, which const-oid refuses");
        assert_eq!(id(&[0x27]).as_deref(), Some("0.39"));
        assert_eq!(id(&[0x4f]).as_deref(), Some("1.39"));
        assert_eq!(id(&[0x88, 0x37, 0x01]).as_deref(), Some("2.999.1"));
        assert_eq!(id(&[0x55, 0x80, 0x01]), None, "an arc in more octets than it needs");
        assert_eq!(id(&[0x55, 0x84]), None, "the last octet continues");
        assert_eq!(id(&[]), None);
    }

    #[test]
    fn times_are_their_der_forms_with_the_utc_pivot() {
        let at =
            |tag: u8, text: &[u8]| time(&Tlv { tag, value: text, encoded: text }).and_then(Instant::to_java_string);
        assert_eq!(at(UTC_TIME, b"491231235959Z").as_deref(), Some("2049-12-31T23:59:59Z"));
        assert_eq!(at(UTC_TIME, b"500101000000Z").as_deref(), Some("1950-01-01T00:00:00Z"));
        assert_eq!(at(GENERALIZED_TIME, b"20550630000000Z").as_deref(), Some("2055-06-30T00:00:00Z"));
        assert_eq!(at(UTC_TIME, b"5001010000Z"), None, "no seconds");
        assert_eq!(at(UTC_TIME, b"500101000000+0100"), None, "an offset");
        assert_eq!(at(GENERALIZED_TIME, b"20550630000000.5Z"), None, "a fraction");
        assert_eq!(at(UTC_TIME, b"501301000000Z"), None, "month 13");
        assert_eq!(at(GENERALIZED_TIME, b"20550630000000"), None, "no zone");
    }

    #[test]
    fn values_are_escaped_as_value_to_string_escapes_them() {
        assert_eq!(escape("a,b"), "a\\,b");
        assert_eq!(escape("  x  "), "\\ \\ x\\ \\ ");
        assert_eq!(escape("   "), "\\ \\ \\ ");
        // After a `\#` prefix a leading space is not escaped, a trailing one still is.
        assert_eq!(escape("\\# x "), "\\# x\\ ");
        assert_eq!(escape(""), "");
    }
}
