//! `PinnedCa`: the certificate authorities one outbound TLS destination is verified against, in place of the
//! public roots — a SIEM collector, a self-managed forge (`common.domain.net.PinnedCa`).
//!
//! **Why per destination.** A server on an internal network carries a certificate from the organisation's own
//! CA; trusting that CA everywhere would widen every outbound connection the control plane makes. Pinned, it is
//! trusted for that destination and nothing else, and the public CAs are not trusted for it. Hostname
//! verification is never relaxed by this: the server's certificate must still name the host as typed.
//!
//! **What is refused, and why at the save**: a certificate that is not a CA (a leaf pasted in place of its issuer
//! would make a self-signed server "trusted" by anyone who copied its certificate, and a leaf rotates without
//! warning); one that has expired or is not yet valid (a TLS stack does not check a trust anchor's own dates);
//! anything that is not a certificate — a private key pasted by mistake is refused **without being echoed**; a
//! bundle past [`MAX_LENGTH`] characters or [`MAX_CERTIFICATES`] certificates.
//!
//! The text is read as BouncyCastle's `PEMParser` reads it — lines, `-----BEGIN` markers, headers, Base64 — and
//! each certificate as [`crate::x509`] describes; the answers, refusals included, are held to
//! `reference/siem/collector-ca/` (`SiemReferenceSetTest`). `cp-outbound`'s `PinnedCa` checks the form only and
//! does not use this yet: the forge connections' port is where the two meet.

use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

use crate::bounded_text::Refused;
use crate::instant::Instant;
use crate::java;
use crate::x509::{self, Certificate};

/// A generous bundle — a root and a few intermediates — counted in UTF-16 units, as `String.length` counts.
pub const MAX_LENGTH: usize = 16_384;

/// More than a chain needs; past it the field is holding something other than a CA.
pub const MAX_CERTIFICATES: usize = 8;

/// Who the messages speak of, so that each screen's refusal names its own field: `field` begins a sentence
/// ("The collector CA"), `server` is the server whose certificate the CA must have issued ("the collector").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subject {
    pub field: &'static str,
    pub server: &'static str,
}

/// One certificate of the bundle; `der` is what the TLS stack is handed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub subject: String,
    pub not_before: Instant,
    pub not_after: Instant,
    pub der: Vec<u8>,
}

/// A bundle, read: the text as stored (trimmed) and at least one anchor, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedCa {
    pem: String,
    anchors: Vec<Anchor>,
}

/// The PEM types `PEMParser` knows. A certificate is read; any other is "something other than certificates" —
/// and an unknown type is not even that, it is unreadable (`unrecognised object`).
const CERTIFICATE_TYPES: &[&str] = &["CERTIFICATE", "X509 CERTIFICATE"];
const OTHER_KNOWN_TYPES: &[&str] = &[
    "CERTIFICATE REQUEST",
    "NEW CERTIFICATE REQUEST",
    "TRUSTED CERTIFICATE",
    "X509 CRL",
    "PKCS7",
    "CMS",
    "ATTRIBUTE CERTIFICATE",
    "EC PARAMETERS",
    "PUBLIC KEY",
    "RSA PUBLIC KEY",
    "RSA PRIVATE KEY",
    "DSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "PRIVATE KEY",
];

impl PinnedCa {
    /// Reads a bundle and checks it is usable at `now`.
    pub fn parse(pem: Option<&str>, now: Instant, subject: &Subject) -> Result<PinnedCa, Refused> {
        let read = PinnedCa::read(pem, subject)?;
        read.require_current(now, subject)?;
        Ok(read)
    }

    /// Reads a bundle somebody has just pasted: [`PinnedCa::parse`], and refused when part of it would not be read.
    ///
    /// BouncyCastle's reader — and `next_object` after it — stops at a `-----BEGIN` line it cannot read, silently,
    /// and hands back what it had: a root followed by a damaged intermediate was pinned as the root alone, and the
    /// handshake failed later with nothing pointing at the paste. Only where the text is typed: a stored bundle is
    /// read as it was accepted ([`PinnedCa::parse`], [`PinnedCa::read`]), since refusing it now would stop a
    /// connection that works with the certificates it has.
    pub fn parse_pasted(pem: Option<&str>, now: Instant, subject: &Subject) -> Result<PinnedCa, Refused> {
        let read = PinnedCa::parse(pem, now, subject)?;
        // Every object the reader returned started at one; one it skipped leaves its marker uncounted. The
        // marker cannot overlap itself, so counting matches is Java's `indexOf(…, at + 1)` loop. Counted in any
        // ASCII case — the reader knows only capitals, so `-----begin` was skipped as silently — and ASCII only,
        // as Java folds it, so that no other letter folds into the marker.
        if read.pem.to_ascii_lowercase().matches("-----begin").count() > read.anchors.len() {
            return Err(Refused(format!(
                "{} has a -----BEGIN line that cannot be read, and what follows it would be ignored. Paste each \
                 certificate whole, from its -----BEGIN CERTIFICATE----- line to its -----END CERTIFICATE----- line.",
                subject.field
            )));
        }
        Ok(read)
    }

    /// Reads a bundle, checking its shape but not its dates — for describing a stored one, which may have expired
    /// since it was saved and must still be shown so that somebody replaces it.
    pub fn read(pem: Option<&str>, subject: &Subject) -> Result<PinnedCa, Refused> {
        let field = subject.field;
        let value = java::trim(pem.unwrap_or(""));
        if value.is_empty() {
            return Err(Refused(format!("{field} is empty.")));
        }
        let length = java::utf16_len(value);
        if length > MAX_LENGTH {
            return Err(Refused(format!("{field} is {length} characters long; at most {MAX_LENGTH} are accepted.")));
        }
        let unreadable = || Refused(format!("{field} is not a readable PEM certificate."));
        let mut anchors = Vec::new();
        let mut lines = java_lines(value).into_iter();
        while let Some(object) = next_object(&mut lines) {
            let (kind, der) = object.ok_or_else(unreadable)?;
            if !CERTIFICATE_TYPES.contains(&kind.as_str()) {
                // The object is not named: if it is a private key, its type is all this says. `PEMParser` reads
                // it first, so a known type that does not decode is unreadable rather than "something other".
                if !OTHER_KNOWN_TYPES.contains(&kind.as_str()) || x509::read_whole(&der).is_none() {
                    return Err(unreadable());
                }
                return Err(Refused(format!(
                    "{field} holds something other than certificates. Paste the CA's certificate in PEM form \
                     (-----BEGIN CERTIFICATE-----); a private key never belongs here."
                )));
            }
            let certificate = Certificate::parse(&der).ok_or_else(unreadable)?;
            if anchors.len() == MAX_CERTIFICATES {
                return Err(Refused(format!("{field} holds more than {MAX_CERTIFICATES} certificates.")));
            }
            anchors.push(anchor_of(&certificate, subject)?.ok_or_else(unreadable)?);
        }
        if anchors.is_empty() {
            return Err(Refused(format!(
                "{field} holds no certificate. Paste it in PEM form, -----BEGIN CERTIFICATE----- included."
            )));
        }
        Ok(PinnedCa { pem: value.to_owned(), anchors })
    }

    /// Every certificate valid at `now`, or the refusal naming the first that is not.
    pub fn require_current(&self, now: Instant, subject: &Subject) -> Result<(), Refused> {
        let field = subject.field;
        for anchor in &self.anchors {
            if now >= anchor.not_after {
                return Err(Refused(format!(
                    "{field} \"{}\" expired on {}.",
                    anchor.subject,
                    instant_text(anchor.not_after)
                )));
            }
            if now < anchor.not_before {
                return Err(Refused(format!(
                    "{field} \"{}\" is not valid before {}.",
                    anchor.subject,
                    instant_text(anchor.not_before)
                )));
            }
        }
        Ok(())
    }

    /// The bundle as stored, trimmed.
    pub fn pem(&self) -> &str {
        &self.pem
    }

    pub fn anchors(&self) -> &[Anchor] {
        &self.anchors
    }

    /// The first certificate's subject: what a screen shows to say which CA is pinned.
    pub fn subject(&self) -> &str {
        self.anchors.first().map_or("", |anchor| anchor.subject.as_str())
    }

    /// The earliest expiry of the bundle: past it, the server is no longer reachable.
    pub fn not_after(&self) -> Instant {
        self.anchors.iter().map(|anchor| anchor.not_after).min().unwrap_or(Instant::of_epoch_second(0))
    }
}

/// A certificate's instants are whole seconds of the years 0000 to 9999, which `to_java_string` always writes.
fn instant_text(at: Instant) -> String {
    at.to_java_string().unwrap_or_default()
}

/// `anchorOf`: the subject, then the CA flag, then the key usage, then the dates — in that order, since the first
/// to fail decides the sentence. `Ok(None)` is unreadable (Java's `RuntimeException`, caught and reworded).
fn anchor_of(certificate: &Certificate<'_>, subject: &Subject) -> Result<Option<Anchor>, Refused> {
    let server = subject.server;
    let Some(name) = certificate.subject() else { return Ok(None) };
    match certificate.is_ca() {
        None => return Ok(None),
        Some(false) => {
            return Err(Refused(format!(
                "\"{name}\" is not a certificate authority (its basic constraints do not say CA): pin the CA that \
                 issued {server}'s certificate, not {server}'s own."
            )));
        }
        Some(true) => {}
    }
    match certificate.may_sign_certificates() {
        None => return Ok(None),
        Some(Some(false)) => {
            return Err(Refused(format!(
                "\"{name}\" may not sign certificates (its key usage lacks keyCertSign), so it cannot have issued \
                 {server}'s."
            )));
        }
        Some(_) => {}
    }
    let (Some(not_before), Some(not_after)) = (certificate.not_before(), certificate.not_after()) else {
        return Ok(None);
    };
    Ok(Some(Anchor { subject: name, not_before, not_after, der: certificate.encoded.to_vec() }))
}

/// `BufferedReader.readLine`: a line ends at `\n`, `\r` or `\r\n`, and a last line with no end is still a line.
fn java_lines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        match rest.find(['\n', '\r']) {
            Some(end) => {
                let (line, after) = rest.split_at(end);
                lines.push(line);
                rest = after.strip_prefix("\r\n").or_else(|| after.get(1..)).unwrap_or("");
            }
            None => {
                lines.push(rest);
                rest = "";
            }
        }
    }
    lines
}

/// `PemReader.readPemObject`, one object: `None` when there is none left — including after a `-----BEGIN` line
/// that is not a well-formed marker, where BouncyCastle stops reading, silently, whatever follows (a pasted bundle
/// is refused for it, by `PinnedCa::parse_pasted`; a stored one is not). `Some(None)`
/// is an object that cannot be read: no end marker, or Base64 that does not decode.
#[allow(clippy::option_option)]
fn next_object<'a>(lines: &mut impl Iterator<Item = &'a str>) -> Option<Option<(String, Vec<u8>)>> {
    const BEGIN: &str = "-----BEGIN ";
    let begin = lines.find(|line| line.starts_with(BEGIN))?;
    let marker = java::trim(begin.get(BEGIN.len()..).unwrap_or(""));
    let dash = marker.find('-').filter(|dash| *dash > 0)?;
    let (kind, tail) = marker.split_at(dash);
    if tail != "-----" {
        return None;
    }
    let end_marker = format!("-----END {kind}-----");
    let mut body = String::new();
    for line in lines.by_ref() {
        if line.contains(':') {
            // A header (`Proc-Type: …`): read and set aside.
            continue;
        }
        if line.starts_with(&end_marker) {
            return Some(decode(&body).map(|der| (kind.to_owned(), der)));
        }
        body.push_str(java::trim(line));
    }
    Some(None)
}

/// BouncyCastle's Base64: spaces, tabs and line ends ignored anywhere, whole groups of four, `=` only at the end,
/// and the unused bits of the last group not checked.
fn decode(body: &str) -> Option<Vec<u8>> {
    let compact: String = body.chars().filter(|c| !matches!(c, ' ' | '\t' | '\n' | '\r')).collect();
    if compact.len().checked_rem(4)? != 0 {
        return None;
    }
    const LENIENT: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    LENIENT.decode(compact.as_bytes()).ok()
}
