//! The control plane's half of the agent protocol, around the result: the bodies it writes — the claim,
//! the hello's answer, the failure report's answer — and the requests it reads — the hello, the sealing-key
//! announcement, the failure report — with each route's refusal in the controller's words.
//!
//! **Byte for byte as the Java control plane**, held to `reference/artifacts/server-wire.json`, which
//! `AgentWireReferenceSetTest` writes with the application's own mappers. Two of them, and the difference
//! is not cosmetic: Spring MVC binds and writes with Spring Boot's Jackson 3 (trailing content refused,
//! nesting to 500), while the failure report — read from its signed bytes — goes through
//! `CoreConfiguration`'s Jackson 2 bean (trailing content never read, nesting to 1,000).
//!
//! Where the body is answered from is the route's (task 2.9); what it says is here.

use crate::coerce;
use crate::jackson::{self, Refused};
use crate::received::Unreadable;
use crate::wire::AssignedTask;
use serde::Serialize;
use serde::ser::SerializeStruct;
use serde_json::ser::{CharEscape, Formatter};
use std::io;
use uuid::Uuid;
use vectispire_domain::FailureKind;
use vectispire_domain::contract;
use vectispire_domain::instant::Instant;
use vectispire_domain::java;

/// A body as Jackson writes one: `serde_json`'s compact form, except that a control character is escaped
/// with **upper-case** hex — `\u001F`, where `serde_json` writes `\u001f`. The other escapes agree: `\"`,
/// `\\`, `\b`, `\f`, `\n`, `\r`, `\t`; nothing else is escaped, not `/`, not DEL, not U+2028.
pub fn write<T: Serialize + ?Sized>(value: &T) -> Result<String, serde_json::Error> {
    let mut out = Vec::with_capacity(256);
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, JacksonEscapes);
    value.serialize(&mut serializer)?;
    // Only `str` content reaches the writer, and the formatter adds ASCII to it.
    String::from_utf8(out).map_err(|error| serde::ser::Error::custom(error.to_string()))
}

struct JacksonEscapes;

impl Formatter for JacksonEscapes {
    fn write_char_escape<W: ?Sized + io::Write>(&mut self, writer: &mut W, escape: CharEscape) -> io::Result<()> {
        let short: &[u8] = match escape {
            CharEscape::Quote => b"\\\"",
            CharEscape::ReverseSolidus => b"\\\\",
            CharEscape::Solidus => b"\\/",
            CharEscape::Backspace => b"\\b",
            CharEscape::FormFeed => b"\\f",
            CharEscape::LineFeed => b"\\n",
            CharEscape::CarriageReturn => b"\\r",
            CharEscape::Tab => b"\\t",
            CharEscape::AsciiControl(byte) => return write!(writer, "\\u{:04X}", byte),
        };
        writer.write_all(short)
    }
}

impl AssignedTask {
    /// The claim's answer, as Spring MVC writes `ScanDispatcher.AgentTask`.
    pub fn to_body(&self) -> Result<String, serde_json::Error> {
        write(self)
    }
}

/// Whether the hello's contract number is this control plane's: `AgentContract.isCompatible`, the
/// number trimmed as `String.trim` trims (control characters too, not a no-break space) and compared
/// for strict equality — `01` and `1.0` are other contracts.
pub fn contract_is_compatible(announced: Option<&str>) -> bool {
    announced.is_some_and(|announced| java::trim(announced) == contract::VERSION)
}

/// The hello's answer — `AgentsController.HelloResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HelloAnswer {
    pub id: Option<Uuid>,
    pub name: Option<String>,
    /// Always this control plane's number, [`contract::VERSION`].
    pub contract_version: &'static str,
    pub max_concurrent: i32,
    pub credentials_mode: Option<String>,
}

impl HelloAnswer {
    pub fn new(
        id: Option<Uuid>,
        name: Option<String>,
        max_concurrent: i32,
        credentials_mode: Option<String>,
    ) -> HelloAnswer {
        HelloAnswer { id, name, contract_version: contract::VERSION, max_concurrent, credentials_mode }
    }

    pub fn to_body(&self) -> Result<String, serde_json::Error> {
        write(self)
    }
}

/// The failure report's answer — `AgentsController.FailureReportResponse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureAnswer {
    /// Back in the queue for another attempt; false when the scan failed for good.
    pub retried: bool,
    pub attempt: i32,
    pub max_attempts: i32,
    /// Failed for good because the report said the failure was permanent.
    pub permanent: bool,
    /// When the scan can be claimed again; `None` when it failed for good.
    pub retry_at: Option<Instant>,
}

impl Serialize for FailureAnswer {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut answer = serializer.serialize_struct("FailureReportResponse", 5)?;
        answer.serialize_field("retried", &self.retried)?;
        answer.serialize_field("attempt", &self.attempt)?;
        answer.serialize_field("maxAttempts", &self.max_attempts)?;
        answer.serialize_field("permanent", &self.permanent)?;
        answer.serialize_field("retryAt", &self.retry_at.map(iso_instant))?;
        answer.end()
    }
}

impl FailureAnswer {
    pub fn to_body(&self) -> Result<String, serde_json::Error> {
        write(self)
    }
}

/// An instant as `DateTimeFormatter.ISO_INSTANT` writes it, which Jackson's `InstantSerializer` uses: the
/// fraction in groups of three digits, none when whole — `…56Z`, `…56.100Z`, `…56.789012Z`.
pub fn iso_instant(instant: Instant) -> String {
    let days = instant.epoch_second.div_euclid(Instant::SECONDS_PER_DAY);
    let second_of_day = instant.epoch_second.rem_euclid(Instant::SECONDS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    let year = if year > 9_999 {
        format!("+{year}")
    } else if year < 0 {
        format!("-{:04}", year.unsigned_abs())
    } else {
        format!("{year:04}")
    };
    let mut text = format!(
        "{year}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        second_of_day / 3_600,
        (second_of_day % 3_600) / 60,
        second_of_day % 60
    );
    let nano = instant.nano;
    if nano > 0 {
        if nano.is_multiple_of(1_000_000) {
            text.push_str(&format!(".{:03}", nano / 1_000_000));
        } else if nano.is_multiple_of(1_000) {
            text.push_str(&format!(".{:06}", nano / 1_000));
        } else {
            text.push_str(&format!(".{nano:09}"));
        }
    }
    text.push('Z');
    text
}

/// Days from 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Wrapping operations on values far inside an `i64`: an instant's day count stays below 2^47.
    let z = days.wrapping_add(719_468);
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era = day_of_era
        .wrapping_sub(day_of_era.wrapping_div(1_460))
        .wrapping_add(day_of_era.wrapping_div(36_524))
        .wrapping_sub(day_of_era.wrapping_div(146_096))
        .wrapping_div(365);
    let day_of_year = day_of_era.wrapping_sub(
        year_of_era
            .wrapping_mul(365)
            .wrapping_add(year_of_era.wrapping_div(4))
            .wrapping_sub(year_of_era.wrapping_div(100)),
    );
    let shifted_month = day_of_year.wrapping_mul(5).wrapping_add(2).wrapping_div(153);
    let day = day_of_year.wrapping_sub(shifted_month.wrapping_mul(153).wrapping_add(2).wrapping_div(5)).wrapping_add(1);
    let month = if shifted_month < 10 { shifted_month.wrapping_add(3) } else { shifted_month.wrapping_sub(9) };
    let year = year_of_era.wrapping_add(era.wrapping_mul(400)).wrapping_add(i64::from(month <= 2));
    (year, u32::try_from(month).unwrap_or_default(), u32::try_from(day).unwrap_or_default())
}

/// The hello as Spring MVC binds `AgentsController.HelloRequest`: snake-case names, `null` or absent as
/// `None`, a scalar as its text (`"contract_version": 1` is the text `1`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HelloRequest {
    pub contract_version: Option<String>,
    /// Unsigned and read by nothing (decision 0031): only the signed announcement is believed.
    pub sealing_public_key: Option<String>,
    pub hostname: Option<String>,
    pub platform: Option<String>,
    pub version: Option<String>,
    pub scanner_engine: Option<String>,
    pub capabilities: Option<String>,
}

impl HelloRequest {
    /// `Ok(None)` for the JSON `null`, which Spring MVC refuses as a missing required body.
    pub fn read(body: &[u8]) -> Result<Option<HelloRequest>, Refused> {
        let document = jackson::prepare(body, jackson::SPRING_MVC)?;
        let text = std::str::from_utf8(&document).map_err(|error| Refused(error.to_string()))?;
        let Some(m) = coerce::root(text, "HelloRequest")? else { return Ok(None) };
        let field =
            |name: &str| -> Result<Option<String>, Refused> { Ok(coerce::last(&m, name, coerce::text)?.flatten()) };
        Ok(Some(HelloRequest {
            contract_version: field("contract_version")?,
            sealing_public_key: field("sealing_public_key")?,
            hostname: field("hostname")?,
            platform: field("platform")?,
            version: field("version")?,
            scanner_engine: field("scanner_engine")?,
            capabilities: field("capabilities")?,
        }))
    }
}

/// The signed sealing-key announcement as Spring MVC binds `AgentsController.SealingKeyRequest`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SealingKeyRequest {
    /// Base64 of the X25519 `SubjectPublicKeyInfo` — check it with `crypto::is_usable_sealing_key`.
    pub public_key: Option<String>,
    /// When the agent made the pair, in epoch milliseconds; `"5"` and `5.7` both read as 5.
    pub generation: Option<i64>,
    pub signature: Option<String>,
}

impl SealingKeyRequest {
    /// `Ok(None)` for the JSON `null`, which Spring MVC refuses as a missing required body.
    pub fn read(body: &[u8]) -> Result<Option<SealingKeyRequest>, Refused> {
        let document = jackson::prepare(body, jackson::SPRING_MVC)?;
        let text = std::str::from_utf8(&document).map_err(|error| Refused(error.to_string()))?;
        let Some(m) = coerce::root(text, "SealingKeyRequest")? else { return Ok(None) };
        Ok(Some(SealingKeyRequest {
            public_key: coerce::last(&m, "public_key", coerce::text)?.flatten(),
            generation: coerce::last(&m, "generation", coerce::boxed_long)?.flatten(),
            signature: coerce::last(&m, "signature", coerce::text)?.flatten(),
        }))
    }

    /// The service's first test before any key is looked at: a generation, and a positive one.
    pub fn has_usable_generation(&self) -> bool {
        self.generation.is_some_and(|generation| generation > 0)
    }
}

/// A failure report as `AgentProtocolService.reportFailure` reads it, after its signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureReport {
    /// From 1: the attempt the claim handed the agent.
    pub attempt: i32,
    /// As sent — the service scrubs it again before it is stored.
    pub reason: Option<String>,
    pub kind: FailureKind,
}

impl FailureReport {
    /// Read with the control plane's Jackson 2 bean; refused — the route's 400 — when Jackson refuses it,
    /// when it is `null`, or when it names no attempt from 1.
    pub fn read(body: &[u8]) -> Result<FailureReport, Unreadable> {
        let document = jackson::prepare(body, jackson::CONTROL_PLANE)?;
        let text = std::str::from_utf8(&document).map_err(|error| Unreadable::Refused(error.to_string()))?;
        let unreadable = || Unreadable::Refused(refusals::failure_unreadable().reason);
        let m = coerce::root(text, "FailureReport")?.ok_or_else(unreadable)?;
        let attempt = coerce::last(&m, "attempt", coerce::boxed_int)?.flatten();
        let reason = coerce::last(&m, "reason", coerce::text)?.flatten();
        let kind = coerce::last(&m, "kind", coerce::text)?.flatten();
        let attempt = attempt.filter(|&attempt| attempt >= 1).ok_or_else(unreadable)?;
        Ok(FailureReport { attempt, reason, kind: failure_kind(kind.as_deref()) })
    }
}

/// `FailureKind.fromWire`: permanent only when it says so, trimmed and in any case; transient otherwise,
/// absent included — an older agent sends no kind.
pub fn failure_kind(value: Option<&str>) -> FailureKind {
    match value {
        Some(value) if java::to_lower_root(java::trim(value)) == "permanent" => FailureKind::Permanent,
        _ => FailureKind::Transient,
    }
}

/// A route's refusal: the status, and the reason `ResponseStatusException` carries into the problem
/// document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRefusal {
    pub status: u16,
    pub reason: String,
}

/// Each refusal of the agent routes, in `AgentsController`'s words. The agent's name is quoted as typed:
/// the reason is JSON-escaped where it is written, not here.
pub mod refusals {
    use super::RouteRefusal;
    use vectispire_crypto::SIGNATURE_HEADER;
    use vectispire_domain::contract;

    fn refusal(status: u16, reason: impl Into<String>) -> RouteRefusal {
        RouteRefusal { status, reason: reason.into() }
    }

    /// 409 and not 400: the request is well formed, the two sides disagree about the protocol, and the fix
    /// is a deployment. A missing number is named `unknown`; anything else as sent, untrimmed.
    pub fn incompatible_contract(announced: Option<&str>) -> RouteRefusal {
        let announced = announced.filter(|announced| !announced.is_empty()).unwrap_or("unknown");
        refusal(
            409,
            format!(
                "This agent speaks contract \"{announced}\" and Vectispire speaks \"{}\". Update the agent.",
                contract::VERSION
            ),
        )
    }

    pub fn sealing_key_unreadable() -> RouteRefusal {
        refusal(400, "A sealing key announcement needs an X25519 public key, a positive generation and a signature.")
    }

    pub fn sealing_key_not_pinned(agent: &str) -> RouteRefusal {
        refusal(
            412,
            format!(
                "No signing key is pinned for agent \"{agent}\", so its sealing key cannot be verified and no credential will be \
                 delegated to it. Pin one from the agents administration screen and configure its private half as \
                 vectispire.agent.signing-key."
            ),
        )
    }

    pub fn sealing_key_not_verified(agent: &str) -> RouteRefusal {
        refusal(
            403,
            format!(
                "The sealing key's signature does not verify against the signing key pinned for \"{agent}\". No credential will be \
                 sealed for it."
            ),
        )
    }

    pub fn sealing_key_stale(agent: &str) -> RouteRefusal {
        refusal(
            409,
            format!(
                "This sealing key is older than the one already accepted for \"{agent}\". Check the agent's clock, or have an \
                 administrator reset its sealing key."
            ),
        )
    }

    /// 403 rather than 401: the API key was accepted, so authenticating again changes nothing.
    pub fn result_not_attested(agent: &str) -> RouteRefusal {
        refusal(
            403,
            format!(
                "This agent's results must be signed: the {SIGNATURE_HEADER} header is absent or does not verify against the key \
                 pinned for \"{agent}\"."
            ),
        )
    }

    pub fn result_unreadable() -> RouteRefusal {
        refusal(400, "The result body is not a readable ScanArtifacts document.")
    }

    pub fn result_no_longer_yours() -> RouteRefusal {
        refusal(409, "This scan is no longer yours: its results were discarded.")
    }

    pub fn failure_not_attested(agent: &str) -> RouteRefusal {
        refusal(
            403,
            format!(
                "This agent's reports must be signed: the {SIGNATURE_HEADER} header is absent or does not verify against the key \
                 pinned for \"{agent}\"."
            ),
        )
    }

    pub fn failure_unreadable() -> RouteRefusal {
        refusal(400, "A failure report needs a JSON body naming the attempt, from 1.")
    }

    pub fn failure_no_longer_yours() -> RouteRefusal {
        refusal(
            409,
            "This scan is not yours at that attempt: the report was already applied, or the lease was taken over.",
        )
    }

    /// The heartbeat of a scan whose lease another worker took over: the agent must give up rather than
    /// hand back a result that would overwrite its successor's.
    pub fn lease_lost() -> RouteRefusal {
        refusal(409, "This scan is no longer yours: its lease was taken over.")
    }

    pub fn not_an_agent() -> RouteRefusal {
        refusal(401, "API key absent, invalid, or without the \"agent\" scope.")
    }

    pub fn disabled(agent: &str) -> RouteRefusal {
        refusal(401, format!("Agent \"{agent}\" is disabled."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_control_character_is_escaped_in_upper_case() {
        assert_eq!(
            write("a\u{1f}\u{0}\t\"\\/\u{7f}\u{2028}é").ok(),
            Some("\"a\\u001F\\u0000\\t\\\"\\\\/\u{7f}\u{2028}é\"".into())
        );
    }

    #[test]
    fn an_instant_is_written_in_groups_of_three_digits() {
        let at = |epoch_second, nano| iso_instant(Instant { epoch_second, nano });
        assert_eq!(at(0, 0), "1970-01-01T00:00:00Z");
        assert_eq!(at(-1, 500_000_000), "1969-12-31T23:59:59.500Z");
        assert_eq!(at(1_792_240_496, 789_012_000), "2026-10-17T12:34:56.789012Z");
        assert_eq!(at(1_792_240_496, 123_456_789), "2026-10-17T12:34:56.123456789Z");
        assert_eq!(at(951_782_400, 0), "2000-02-29T00:00:00Z");
        assert_eq!(at(253_402_300_800, 0), "+10000-01-01T00:00:00Z");
    }

    #[test]
    fn the_contract_is_compared_once_trimmed_as_java_trims() {
        assert!(contract_is_compatible(Some("\u{0}1\u{1f}")));
        assert!(!contract_is_compatible(Some("\u{a0}1")));
        assert!(!contract_is_compatible(Some("01")));
        assert!(!contract_is_compatible(None));
        assert_eq!(refusals::incompatible_contract(Some("")).reason, refusals::incompatible_contract(None).reason);
        assert!(refusals::incompatible_contract(Some(" ")).reason.contains("\" \""));
    }
}
