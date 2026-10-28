//! `CefEvent`: an immutable ArcSight Common Event Format event,
//! `CEF:0|Vectispire|ASPM|<version>|<signature id>|<name>|<severity>|<extension>`.
//!
//! **Escaping is a security control here, not formatting.** Several extension values come from whoever is on the
//! other side of a form: the username a sign-in attempt typed, a resource identifier, an audit description. A
//! username of `x\nCEF:0|Vectispire|ASPM|1|VECTI-SEC-018|…` written raw would be a second event in every
//! line-oriented collector — a forged alarm, or a forged all-clear. So:
//!
//! - in the header, `\` and `|` are escaped, as the specification requires;
//! - in extension values, `\` and `=` are escaped, and CR and LF become `\r` and `\n`. A pipe needs no escape
//!   there — parsers split the header on the first seven — and escaping one would print a stray backslash;
//! - every other control character, in the header or in a value, becomes a space.
//!
//! Extension keys are ours, never a caller's: a bad one is a programming error, refused rather than escaped,
//! because an escaped key is still a key no SIEM will recognise.
//!
//! **The severity is the event's.** It is what the header states, what the syslog priority is derived from and
//! what the configured minimum is compared with — one value, so the three cannot disagree.
//!
//! The line is held byte for byte to Java's by `reference/siem/` (`SiemReferenceSetTest`).

use crate::instant::Instant;
use crate::java;
use crate::severity::Severity;
use crate::siem::event_type::SecurityEventType;

/// An event that cannot be built: Java's `IllegalArgumentException` or `IllegalStateException`, a programming
/// error of the emitter's — never something a user typed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidEvent(pub String);

/// One CEF event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CefEvent {
    event_type: SecurityEventType,
    timestamp: Instant,
    message: Option<String>,
    extensions: Vec<(String, String)>,
    cef_severity: u8,
}

impl CefEvent {
    /// The canonical constructor: every key checked, the severity on the CEF scale.
    ///
    /// The timestamp is required, never "now": the moment is the caller's — the audit entry's, the issue's — and
    /// a domain type reading the wall clock was a second time source no test could pin. `extensions` keep their
    /// order; a key given twice keeps its first place and its last value, as Java's `LinkedHashMap` does.
    pub fn new(
        event_type: SecurityEventType,
        timestamp: Instant,
        message: Option<&str>,
        extensions: &[(&str, &str)],
        cef_severity: i32,
    ) -> Result<CefEvent, InvalidEvent> {
        let Some(cef_severity) = u8::try_from(cef_severity).ok().filter(|severity| *severity <= 10) else {
            return Err(InvalidEvent(format!("A CEF severity is 0 to 10, not {cef_severity}")));
        };
        let mut ordered = Vec::with_capacity(extensions.len());
        for (key, value) in extensions {
            put(&mut ordered, key, value);
        }
        for (key, _) in &ordered {
            require_key(key)?;
        }
        Ok(CefEvent { event_type, timestamp, message: message.map(str::to_owned), extensions: ordered, cef_severity })
    }

    /// An event at its type's severity.
    pub fn at_type_severity(
        event_type: SecurityEventType,
        timestamp: Instant,
        message: Option<&str>,
        extensions: &[(&str, &str)],
    ) -> Result<CefEvent, InvalidEvent> {
        CefEvent::new(event_type, timestamp, message, extensions, i32::from(event_type.cef_severity()))
    }

    /// `timestamp`: when it happened, by the caller's clock.
    pub fn builder(event_type: SecurityEventType, timestamp: Instant) -> CefEventBuilder {
        CefEventBuilder {
            event_type,
            timestamp,
            message: None,
            extensions: Vec::new(),
            cef_severity: event_type.cef_severity(),
            refused: None,
        }
    }

    pub fn event_type(&self) -> SecurityEventType {
        self.event_type
    }

    pub fn timestamp(&self) -> Instant {
        self.timestamp
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// The extensions in their order, as given — `rt`, `outcome` and `msg` are added by
    /// [`CefEvent::to_cef_string`].
    pub fn extensions(&self) -> &[(String, String)] {
        &self.extensions
    }

    pub fn cef_severity(&self) -> u8 {
        self.cef_severity
    }

    /// The event as one CEF line.
    ///
    /// `device_version` is the product's version, or `None` when nothing states one — the field is then left
    /// empty rather than filled with a number nobody shipped.
    pub fn to_cef_string(&self, device_version: Option<&str>) -> String {
        let mut line = String::from("CEF:0|Vectispire|ASPM|");
        line.push_str(&escape_header(device_version));
        line.push('|');
        line.push_str(&escape_header(Some(self.event_type.signature_id())));
        line.push('|');
        line.push_str(&escape_header(Some(self.event_type.description())));
        line.push('|');
        line.push_str(&self.cef_severity.to_string());
        line.push('|');

        // `toEpochMilli` overflows only some 292 million years from now, where Java throws; saturating keeps
        // the formatter total for a value no clock produces.
        let rt = self.timestamp.to_epoch_milli().unwrap_or(if self.timestamp.epoch_second < 0 {
            i64::MIN
        } else {
            i64::MAX
        });
        let mut fields: Vec<(String, String)> = vec![
            ("rt".to_owned(), rt.to_string()),
            ("outcome".to_owned(), self.event_type.outcome().wire_name().to_owned()),
        ];
        for (key, value) in &self.extensions {
            put(&mut fields, key, value);
        }
        if let Some(message) = self.message.as_deref().filter(|message| !java::is_blank(message)) {
            put(&mut fields, "msg", message);
        }
        let extension: Vec<String> =
            fields.iter().map(|(key, value)| format!("{key}={}", escape_extension_value(Some(value)))).collect();
        line.push_str(&extension.join(" "));
        line
    }
}

/// `CefEvent.Builder`. A refusal — an issue's severity given to a type whose severity is fixed — is kept and
/// answered by [`CefEventBuilder::build`], where Java throws at the call: either way no event is made.
#[derive(Debug, Clone)]
pub struct CefEventBuilder {
    event_type: SecurityEventType,
    timestamp: Instant,
    message: Option<String>,
    extensions: Vec<(String, String)>,
    cef_severity: u8,
    refused: Option<InvalidEvent>,
}

impl CefEventBuilder {
    /// The severity of the issue the event reports on, which becomes the event's
    /// ([`SecurityEventType::cef_severity_of`]). Refused for a type whose severity is fixed: a SOC's rules were
    /// written against that one, and an emitter is not where it changes.
    pub fn issue_severity(mut self, issue_severity: Severity) -> Self {
        if self.event_type.follows_issue_severity() {
            self.cef_severity = SecurityEventType::cef_severity_of(issue_severity);
        } else if self.refused.is_none() {
            self.refused = Some(InvalidEvent(format!("{} has a fixed CEF severity", self.event_type.wire_name())));
        }
        self
    }

    pub fn message<'a>(mut self, message: impl Into<Option<&'a str>>) -> Self {
        self.message = message.into().map(str::to_owned);
        self
    }

    /// `suser`: the account that acted, as the audit entry names it.
    pub fn user<'a>(self, username: impl Into<Option<&'a str>>) -> Self {
        self.put_present("suser", username.into())
    }

    /// `src`: the client address, as the audit entry or the caller recorded it.
    pub fn source_ip<'a>(self, ip: impl Into<Option<&'a str>>) -> Self {
        self.put_present("src", ip.into())
    }

    /// `act`: what was done, as the audit log names the operation.
    pub fn action<'a>(self, action: impl Into<Option<&'a str>>) -> Self {
        self.put_present("act", action.into())
    }

    /// `externalId`: the outbox message identifier, which is what a receiver deduplicates on.
    pub fn external_id<'a>(self, id: impl Into<Option<&'a str>>) -> Self {
        self.put_present("externalId", id.into())
    }

    /// `cs1`: the resource acted upon — an issue, an account, a key, a setting.
    pub fn target<'a>(self, target: impl Into<Option<&'a str>>) -> Self {
        self.labelled("cs1", "Target", target.into())
    }

    /// `cs2`: the user agent the request carried.
    pub fn user_agent<'a>(self, user_agent: impl Into<Option<&'a str>>) -> Self {
        self.labelled("cs2", "UserAgent", user_agent.into())
    }

    /// `cs3`: a CVE, a rule or a secret identifier.
    pub fn identifier<'a>(self, identifier: impl Into<Option<&'a str>>) -> Self {
        self.labelled("cs3", "Identifier", identifier.into())
    }

    /// `cs4`: the package or component concerned.
    pub fn component<'a>(self, component: impl Into<Option<&'a str>>) -> Self {
        self.labelled("cs4", "Component", component.into())
    }

    /// Any extension, kept even when blank (Java's `extension`); an absent value is no field. The key is checked
    /// by [`CefEventBuilder::build`].
    pub fn extension<'a>(mut self, key: &str, value: impl Into<Option<&'a str>>) -> Self {
        if let Some(value) = value.into() {
            put(&mut self.extensions, key, value);
        }
        self
    }

    pub fn build(self) -> Result<CefEvent, InvalidEvent> {
        if let Some(refused) = self.refused {
            return Err(refused);
        }
        for (key, _) in &self.extensions {
            require_key(key)?;
        }
        Ok(CefEvent {
            event_type: self.event_type,
            timestamp: self.timestamp,
            message: self.message,
            extensions: self.extensions,
            cef_severity: self.cef_severity,
        })
    }

    fn labelled(mut self, slot: &str, label: &str, value: Option<&str>) -> Self {
        if let Some(value) = value.filter(|value| !java::is_blank(value)) {
            put(&mut self.extensions, &format!("{slot}Label"), label);
            put(&mut self.extensions, slot, value);
        }
        self
    }

    fn put_present(mut self, key: &str, value: Option<&str>) -> Self {
        if let Some(value) = value.filter(|value| !java::is_blank(value)) {
            put(&mut self.extensions, key, value);
        }
        self
    }
}

/// `LinkedHashMap.put`: a new key goes last, a known one keeps its place and takes the new value.
fn put(fields: &mut Vec<(String, String)>, key: &str, value: &str) {
    match fields.iter_mut().find(|(existing, _)| existing == key) {
        Some((_, existing)) => value.clone_into(existing),
        None => fields.push((key.to_owned(), value.to_owned())),
    }
}

/// `[A-Za-z0-9]+`, which is what Java's pattern admits: ASCII only.
fn require_key(key: &str) -> Result<(), InvalidEvent> {
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(InvalidEvent(format!("Not a CEF extension key: {key}")));
    }
    Ok(())
}

/// A header field: `\` and `|` escaped, then every control character a space — CR and LF included, which the
/// header has no escape for. Absent is empty.
pub fn escape_header(value: Option<&str>) -> String {
    let Some(value) = value else { return String::new() };
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            c if is_control(c) => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// An extension value: `\` and `=` escaped, CR and LF as `\r` and `\n`, every other control character a space.
/// One pass gives what Java's chain of `replace` calls gives: no replacement writes a character an earlier one
/// would have rewritten.
pub fn escape_extension_value(value: Option<&str>) -> String {
    let Some(value) = value else { return String::new() };
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            c if is_control(c) => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// C0, DEL, C1 and the Unicode line and paragraph separators, which some collectors split on.
fn is_control(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{2028}' | '\u{2029}')
}
