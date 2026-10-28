//! `SiemSeverityFilter`: which events the configured minimum severity lets through.
//!
//! The setting speaks the product's severities and an event carries a CEF severity from 0 to 10. The bridge is
//! the CEF convention every SIEM already renders its colours by: 9–10 very high, 7–8 high, 4–6 medium, 0–3 low.
//! So `HIGH` forwards 7 and above, and a SOC reading the severity column sees the band the filter used.

use crate::java;
use crate::severity::Severity;
use crate::siem::cef::CefEvent;
use crate::siem::event_type::SecurityEventType;

/// Whether this event is forwarded under this stored minimum — on the **event's** severity, which for a type that
/// follows its issue is not the type's: deciding on the type kept every deadline breach, a critical issue's
/// included, under the factory minimum.
///
/// **Absent or blank sends everything**: no threshold is not a threshold of "nothing". **An unreadable value sends
/// everything too** — a row edited by hand, or a severity a later version adds: for a security feed the failure
/// worth having is noise in a SOC, not silence nobody sees. [`SecurityEventType::PingTest`] always passes: it
/// tests the destination, and a filter that swallowed it would fail the connection test on a working collector.
pub fn admits(event: &CefEvent, stored_minimum: Option<&str>) -> bool {
    if event.event_type() == SecurityEventType::PingTest {
        return true;
    }
    minimum_of(stored_minimum).is_none_or(|floor| event.cef_severity() >= floor)
}

/// The lowest CEF severity a stored minimum forwards, or `None` when it forwards everything. `isBlank`, then
/// `String.trim` and `toUpperCase(Locale.ROOT)` against the enum's names, as Java reads the column.
pub fn minimum_of(stored_minimum: Option<&str>) -> Option<u8> {
    let stored = stored_minimum.filter(|stored| !java::is_blank(stored))?;
    let normalized = java::trim(stored).to_uppercase();
    let severity =
        [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Negligible, Severity::Unknown]
            .into_iter()
            .find(|severity| severity.wire_name().to_uppercase() == normalized)?;
    cef_floor(severity)
}

/// The CEF band's lower edge. A match without a wildcard, so a severity added to [`Severity`] has to be placed
/// here; `NEGLIGIBLE` and `UNKNOWN` are not offered by the screen, and both mean "the lowest".
fn cef_floor(severity: Severity) -> Option<u8> {
    match severity {
        Severity::Critical => Some(9),
        Severity::High => Some(7),
        Severity::Medium => Some(4),
        Severity::Low | Severity::Negligible | Severity::Unknown => None,
    }
}
