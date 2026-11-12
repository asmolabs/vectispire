//! `SyslogMessage`: a CEF event as an RFC 5424 syslog message, and its framing on a stream.
//!
//! ```text
//! <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
//! <82>1 2026-09-26T10:00:00.123Z vectispire-1 vectispire - VECTI-SEC-007 - CEF:0|Vectispire|…
//! ```
//!
//! - **Facility 10** (security/authorization), which every syslog daemon routes as `authpriv`. The severity is
//!   derived from the CEF one, so a collector filtering on the header and one reading the CEF agree.
//! - **MSGID is the CEF signature identifier**, so a collector can route without parsing the payload.
//! - **No BOM before MSG.** CEF parsers read `CEF:0|` at the first byte: a BOM there makes a well-formed event
//!   unparseable on the receivers that matter.
//!
//! On TCP and TLS, **octet counting** (RFC 6587 §3.4.1): the frame is the message's length in bytes, a space,
//! then the message. Newline framing is exactly the one a log injection needs — a line break smuggled into a
//! field becomes a second, forged event; CEF escapes line breaks already, and the framing does not depend on it.

use crate::siem::cef::CefEvent;

/// Security/authorization messages, RFC 5424 §6.2.1.
pub const FACILITY: u8 = 10;

pub const APP_NAME: &str = "vectispire";

const NIL: &str = "-";

/// RFC 5424 limits HOSTNAME to 255 printable characters.
const MAX_HOSTNAME: usize = 255;

/// The syslog message carrying one CEF line, at the event's own severity and stamped with its time.
///
/// `hostname` is this instance's name as the header states it; anything outside printable US-ASCII is dropped,
/// and nothing left becomes the NILVALUE — a space in the header would shift every field after it.
pub fn format(event: &CefEvent, hostname: Option<&str>, cef: &str) -> String {
    format!(
        "<{}>1 {} {} {APP_NAME} {NIL} {} {NIL} {cef}",
        priority(event.cef_severity()),
        timestamp(event),
        header_token(hostname, MAX_HOSTNAME),
        header_token(Some(event.event_type().signature_id()), 32),
    )
}

/// `MSG-LEN SP SYSLOG-MSG`, the length counted in bytes of the UTF-8 encoding, not in characters: a character
/// count would cut a frame short and the receiver would read the leftover as the start of the next one.
pub fn octet_counted(message: &str) -> Vec<u8> {
    let mut frame = format!("{} ", message.len()).into_bytes();
    frame.extend_from_slice(message.as_bytes());
    frame
}

/// `facility × 8 + severity`.
pub fn priority(cef_severity: u8) -> u8 {
    // At most 10 × 8 + 5: no overflow to guard, and the lint ceilings count operators, so it is spelled checked.
    FACILITY.saturating_mul(8).saturating_add(syslog_severity(cef_severity))
}

/// The CEF band as a syslog severity: very high is critical, high is error, medium is warning, low is notice.
/// Nothing maps to alert or emergency — those page somebody at night, and a forwarded application event has no
/// business deciding that for a SOC.
pub fn syslog_severity(cef_severity: u8) -> u8 {
    match cef_severity {
        9.. => 2,
        7..=8 => 3,
        4..=6 => 4,
        _ => 5,
    }
}

/// `yyyy-MM-dd'T'HH:mm:ss.SSS'Z'` in UTC — milliseconds, which is what CEF's `rt` carries, so the two agree.
///
/// `yyyy` is the year of the era, padded to four digits and signed past them (`EXCEEDS_PAD`); no clock this runs
/// on reaches either difference from the plain year, and both are spelled as Java spells them.
fn timestamp(event: &CefEvent) -> String {
    let Some(at) = event.timestamp().to_utc() else { return NIL.to_owned() };
    let year_of_era = if at.year >= 1 { at.year } else { 1i64.saturating_sub(at.year) };
    let year = if year_of_era > 9_999 { format!("+{year_of_era}") } else { format!("{year_of_era:04}") };
    format!(
        "{year}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        at.month,
        at.day,
        at.hour,
        at.minute,
        at.second,
        at.nano.checked_div(1_000_000).unwrap_or(0)
    )
}

/// Printable US-ASCII only (33 to 126), at most `max_length` of it; nothing left is the NILVALUE.
fn header_token(value: Option<&str>, max_length: usize) -> String {
    let Some(value) = value else { return NIL.to_owned() };
    let printable: String = value.chars().filter(|c| ('!'..='~').contains(c)).take(max_length).collect();
    if printable.is_empty() { NIL.to_owned() } else { printable }
}
