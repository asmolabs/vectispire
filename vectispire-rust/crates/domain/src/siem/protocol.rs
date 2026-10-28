//! `SiemProtocol`: how the SIEM configuration says events travel.
//!
//! **What is stored is what is spoken.** It was not, once: every event went out as an HTTP POST whatever this
//! said. Each value names a transport — see [`crate::siem::endpoint`] for the endpoint each reads and
//! [`crate::siem::syslog`] for the framing of the three syslog ones.

/// The four values the settings screen offers and the published contract declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SiemProtocol {
    Webhook,
    SyslogUdp,
    SyslogTcp,
    SyslogTls,
}

impl SiemProtocol {
    pub const ALL: [SiemProtocol; 4] =
        [SiemProtocol::Webhook, SiemProtocol::SyslogUdp, SiemProtocol::SyslogTcp, SiemProtocol::SyslogTls];

    /// The Java constant's name, which is what the column stores.
    pub const fn name(self) -> &'static str {
        match self {
            SiemProtocol::Webhook => "WEBHOOK",
            SiemProtocol::SyslogUdp => "SYSLOG_UDP",
            SiemProtocol::SyslogTcp => "SYSLOG_TCP",
            SiemProtocol::SyslogTls => "SYSLOG_TLS",
        }
    }

    /// Whether a configured header travels with each event. Only an HTTP request has headers; a syslog frame has
    /// nowhere to put one, and pretending otherwise would let a screen collect a credential that is never used.
    pub fn carries_headers(self) -> bool {
        self == SiemProtocol::Webhook
    }

    /// `byName`: the protocol a submitted value names, case aside, or `None`. `String.trim`, then
    /// `toUpperCase(Locale.ROOT)` — Rust's `to_uppercase` makes the same full mappings (`ſ` is an `S`).
    pub fn by_name(value: Option<&str>) -> Option<SiemProtocol> {
        let normalized = crate::java::trim(value?).to_uppercase();
        SiemProtocol::ALL.into_iter().find(|protocol| protocol.name() == normalized)
    }
}
