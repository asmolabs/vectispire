//! The SIEM export's configuration and its connection test — `SiemExporterService` and `SiemConfigView`.
//!
//! Events do not pass here: [`crate::SiemEvents`] queues them in the transaction that caused them and
//! [`crate::SiemDelivery`] sends them after it commits. What does leave from here, synchronously, is the stop notice
//! to a collector being left and the connection test's health check.

use std::sync::Arc;

use time::OffsetDateTime;
use vectispire_cp_audit::{AuditLog, AuditOperation, Clock, RequestActor, Signal};
use vectispire_cp_crypto::Encryption;
use vectispire_cp_db::{Db, Mode};
use vectispire_cp_settings::THRESHOLDS;
use vectispire_domain::bounded_text;
use vectispire_domain::instant::Instant;
use vectispire_domain::java;
use vectispire_domain::secret::Secret;
use vectispire_domain::siem::{CefEvent, CollectorCa, SecurityEventType, SiemEndpoint, SiemProtocol, endpoint};

use crate::error::SiemError;
use crate::events::instant;
use crate::persistence::{self, ConfigRow, SINGLETON_ID};
use crate::transport::{SendError, Transport};

/// Binds the stored header to its own column, so a ciphertext moved elsewhere does not decrypt. Stored with every
/// ciphertext: it must not move.
pub const AUTH_HEADER_CONTEXT: &str = "siem_config:auth_header";

/// How a header that cannot be read is named in the log.
pub const AUTH_HEADER_LABEL: &str = "The SIEM authorization header";

/// The width of `endpoint`.
pub const MAX_ENDPOINT_LENGTH: usize = 1_024;

/// Encrypted, 1,500 ASCII characters become at most 2,043: V32 gave the column 2,048.
pub const MAX_AUTH_HEADER_LENGTH: usize = 1_500;

/// The test's answer when the policy refused the destination: a closed port and a filtered one are not told apart.
pub const REFUSED_BY_POLICY: &str = "Refused by the outbound policy: this destination is not allowed. A collector on \
the internal network needs an administrator to enable “Allow a private SIEM destination”; Vectispire's own database, \
its Docker daemon and the instance metadata endpoint are refused in every case.";

/// The test's answer for every other failure: the socket's own words stay in the server log.
pub const NOT_DELIVERED: &str = "The event was not delivered: the collector could not be reached, or did not accept it. The cause is in the server log.";

/// The configuration as the layers above the services hold it — `SiemConfigView`.
///
/// **The authorization header is not here, only whether one is set.** The column holds its ciphertext, which no route
/// has a use for. **The pinned CA is here in full**, being public, so the form can show and resubmit it, with the
/// subject and earliest expiry read from it — `None` for both when none is pinned, or when the stored text no longer
/// reads as one (a row edited by hand: the delivery refuses it, and the screen shows the PEM to replace).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiemConfigView {
    pub id: i64,
    pub enabled: bool,
    pub protocol: String,
    pub endpoint: Option<String>,
    pub has_auth_header: bool,
    pub min_severity: String,
    pub tls_ca_pem: Option<String>,
    pub tls_ca_subject: Option<String>,
    pub tls_ca_not_after: Option<Instant>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl SiemConfigView {
    fn of(row: &ConfigRow) -> SiemConfigView {
        let ca = row
            .tls_ca_pem
            .as_deref()
            .filter(|pem| !java::is_blank(pem))
            .and_then(|pem| CollectorCa::read(Some(pem)).ok());
        SiemConfigView {
            id: row.id,
            enabled: row.enabled,
            protocol: row.protocol.clone(),
            endpoint: row.endpoint.clone(),
            has_auth_header: row.auth_header.as_deref().is_some_and(|header| !java::is_blank(header)),
            min_severity: row.min_severity.clone(),
            tls_ca_pem: row.tls_ca_pem.clone(),
            tls_ca_subject: ca.as_ref().map(|ca| ca.subject().to_owned()),
            tls_ca_not_after: ca.as_ref().map(CollectorCa::not_after),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// What a save asks for — the route's body, field by field.
#[derive(Debug, Clone, Default)]
pub struct SiemConfigUpdate {
    pub enabled: bool,
    /// Absent or blank is the webhook.
    pub protocol: Option<String>,
    pub endpoint: Option<String>,
    /// Absent or blank keeps the stored header — unless the endpoint moved.
    pub auth_header: Option<Secret>,
    /// Absent or blank is `HIGH`.
    pub min_severity: Option<String>,
    /// The collector CA for syslog over TLS: absent keeps the stored one, blank removes it. Absent keeps because a
    /// client written before the field existed would otherwise unpin the CA at every save; the screen always sends
    /// what it shows.
    pub tls_ca_pem: Option<String>,
}

/// The connection test's answer: an outcome, never the socket's words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestResult {
    pub success: bool,
    pub message: String,
    pub status_code: i32,
}

impl TestResult {
    fn refused(message: impl Into<String>) -> TestResult {
        TestResult { success: false, message: message.into(), status_code: 0 }
    }
}

/// The collector a stored configuration exports to, with what it takes to reach it.
struct Collector {
    protocol: SiemProtocol,
    written: String,
    endpoint: SiemEndpoint,
    header: Option<Secret>,
    ca: Option<CollectorCa>,
}

impl Collector {
    /// The same transport to the same endpoint as written: a new severity or header does not leave it.
    fn same_destination_as(&self, row: &ConfigRow) -> bool {
        self.protocol.name() == row.protocol
            && row.endpoint.as_deref().is_some_and(|next| self.written == java::trim(next))
    }
}

/// The service.
pub struct SiemExporterService {
    db: Db,
    transport: Arc<dyn Transport>,
    encryption: Arc<Encryption>,
    audit: AuditLog,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for SiemExporterService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SiemExporterService").finish_non_exhaustive()
    }
}

impl SiemExporterService {
    pub fn new(
        db: Db,
        transport: Arc<dyn Transport>,
        encryption: Arc<Encryption>,
        audit: AuditLog,
        clock: Arc<dyn Clock>,
    ) -> SiemExporterService {
        SiemExporterService { db, transport, encryption, audit, clock }
    }

    /// The stored configuration, or `None` before the first save.
    pub async fn get_config(&self) -> Result<Option<SiemConfigView>, SiemError> {
        Ok(persistence::find(&self.db).await?.as_ref().map(SiemConfigView::of))
    }

    /// The clock at the microsecond, as `CoreConfiguration.clock()` ticks.
    fn now(&self) -> OffsetDateTime {
        let now = self.clock.now();
        now.replace_microsecond(now.microsecond()).unwrap_or(now)
    }

    /// Stores the configuration and audits the change — never the header, which is a credential, in an entry that is
    /// never purged.
    ///
    /// **Every field is checked before the row is touched**, so a refusal leaves the stored configuration exactly as
    /// it was: each of these reached its column unchecked once, and a value past it was refused by the database as a
    /// 500.
    pub async fn save_config(
        &self,
        update: SiemConfigUpdate,
        actor: &RequestActor,
    ) -> Result<SiemConfigView, SiemError> {
        let protocol = match update.protocol.as_deref().filter(|value| !java::is_blank(value)) {
            None => SiemProtocol::Webhook,
            Some(value) => parse_protocol(value)?,
        };
        let threshold = match update.min_severity.as_deref().filter(|value| !java::is_blank(value)) {
            None => "HIGH".to_owned(),
            Some(value) => threshold(value)?,
        };
        let endpoint_text = update.endpoint.as_deref();
        if let Some(text) = endpoint_text {
            bounded_text::within(java::trim(text), MAX_ENDPOINT_LENGTH, "The endpoint").map_err(invalid)?;
        }
        // **Read for its protocol at the save, not discovered at the first event.** A syslog endpoint typed as a URL,
        // or a URL saved under a syslog protocol, was stored and then failed every delivery for four hours. An enabled
        // export with no endpoint is refused too: it would have queued nothing and said so to nobody.
        let has_endpoint = endpoint_text.is_some_and(|text| !java::is_blank(text));
        if has_endpoint {
            endpoint::parse(protocol, endpoint_text).map_err(invalid)?;
        } else if update.enabled {
            return Err(SiemError::InvalidInput("An enabled SIEM export needs an endpoint.".to_owned()));
        }
        let header_given = update.auth_header.as_ref().filter(|header| !java::is_blank(header.expose()));
        if let Some(header) = header_given {
            if !protocol.carries_headers() {
                // Refused rather than stored: a credential kept for a transport that cannot send it is a secret at
                // rest with no purpose, and the screen would claim it was in use.
                return Err(SiemError::InvalidInput(
                    "The authorization header applies to the webhook protocol only: a syslog frame has nowhere to \
                     carry it."
                        .to_owned(),
                ));
            }
            require_usable_header(java::trim(header.expose()))?;
        }
        let ca_given = update.tls_ca_pem.as_deref().filter(|pem| !java::is_blank(pem));
        if ca_given.is_some() && protocol != SiemProtocol::SyslogTls {
            // Refused rather than stored, like a header sent for syslog: the screen would show a CA as pinned for a
            // transport that never reads it.
            return Err(SiemError::InvalidInput(
                "A collector CA applies to syslog over TLS only: the other protocols do not verify a collector's \
                 certificate against it."
                    .to_owned(),
            ));
        }
        let now = self.now();
        let pinned = match ca_given {
            Some(pem) => Some(CollectorCa::parse_pasted(Some(pem), instant(now)).map_err(invalid)?),
            None => None,
        };

        let stored = persistence::find(&self.db).await?;
        let exists = stored.is_some();
        let mut row = stored.unwrap_or_else(|| ConfigRow {
            id: SINGLETON_ID,
            enabled: false,
            protocol: SiemProtocol::Webhook.name().to_owned(),
            endpoint: None,
            auth_header: None,
            tls_ca_pem: None,
            min_severity: "HIGH".to_owned(),
            created_at: now,
            updated_at: now,
        });
        // Read before the row changes: the collector being left is the one configured now.
        let leaving = self.collector_of(&row).await;
        // **A new destination does not inherit the old credential.** A header is issued for one collector; pointing
        // the export elsewhere — the security lead's own host included — requires typing it again.
        let previous = java::trim(row.endpoint.as_deref().unwrap_or("")).to_owned();
        let next = java::trim(endpoint_text.unwrap_or("")).to_owned();
        if previous != next && header_given.is_none() {
            row.auth_header = None;
        }
        row.enabled = update.enabled;
        row.protocol = protocol.name().to_owned();
        // Stored as it was checked: trimmed (the Java fix of the same day — it was checked trimmed and stored as typed).
        row.endpoint = endpoint_text.map(|text| java::trim(text).to_owned());
        // **Blank keeps the stored header**: the response never sends it back, so the form cannot resubmit it.
        // **Encrypted like every other credential**, bound to its column.
        if let Some(header) = header_given {
            row.auth_header = Some(self.encryption.encrypt(java::trim(header.expose()), AUTH_HEADER_CONTEXT).await?);
        }
        if protocol != SiemProtocol::SyslogTls || update.tls_ca_pem.as_deref().is_some_and(java::is_blank) {
            // Leaving TLS drops the CA with it: kept, it would come back unannounced the day the protocol is set to TLS
            // again, for a collector it was perhaps never issued for.
            row.tls_ca_pem = None;
        } else if let Some(pinned) = &pinned {
            row.tls_ca_pem = Some(pinned.pem().to_owned());
        }
        row.min_severity = threshold;
        row.updated_at = now;
        self.write(&row, exists).await?;

        // The collector being left hears it, before the silence: a feed that stops is otherwise read by a SOC as an
        // outage — or not noticed at all — when it was a decision. Sent after the save, so it announces a change that
        // happened, and before the audit entry, which records whether it arrived.
        let notice = match leaving.filter(|previous| !row.enabled || !previous.same_destination_as(&row)) {
            Some(previous) => self.announce_stop(&previous, row.enabled, actor).await,
            None => String::new(),
        };

        // Signalled, and sent to the collector configured by this very save when it is on: a SOC should hear about
        // the export being repointed, at the new collector as at the old one.
        let description = format!(
            "SIEM configuration updated (enabled={}, protocol={}, minimum severity={}{}){notice}",
            row.enabled,
            row.protocol,
            row.min_severity,
            if row.tls_ca_pem.is_some() { ", collector CA pinned" } else { "" }
        );
        self.audit
            .record(
                actor
                    .entry(AuditOperation::SettingUpdated, &row.id.to_string(), &description)
                    .signalling(Signal(SecurityEventType::SecuritySettingChanged.wire_name())),
            )
            .await;
        Ok(SiemConfigView::of(&row))
    }

    /// The row, in a transaction of its own: inserted the first time, updated after.
    async fn write(&self, row: &ConfigRow, exists: bool) -> Result<(), SiemError> {
        let mut tx = self.db.begin(Mode::ReadWrite).await.map_err(|error| SiemError::Database(error.to_string()))?;
        let written =
            if exists { persistence::update(&mut tx, row).await } else { persistence::insert(&mut tx, row).await };
        match written {
            Ok(_) => tx.commit().await.map_err(|error| SiemError::Database(error.to_string())),
            Err(failed) => {
                let _ = tx.rollback().await;
                Err(failed.into())
            }
        }
    }

    /// The collector a stored configuration exports to — or `None` when it exports nowhere, or its row can no longer
    /// be read (then there is no collector to tell, and the delivery would have refused it too).
    async fn collector_of(&self, row: &ConfigRow) -> Option<Collector> {
        let protocol = SiemProtocol::by_name(Some(&row.protocol))?;
        let written = row.endpoint.as_deref().filter(|endpoint| row.enabled && !java::is_blank(endpoint))?;
        let endpoint = match endpoint::parse(protocol, Some(written)) {
            Ok(endpoint) => endpoint,
            Err(unreadable) => {
                tracing::warn!("The SIEM collector being left could not be read, so it was not told: {unreadable}");
                return None;
            }
        };
        let header = match row.auth_header.as_deref().filter(|_| protocol.carries_headers()) {
            Some(stored) => Some(self.encryption.read_secret(stored, AUTH_HEADER_CONTEXT, AUTH_HEADER_LABEL).await),
            None => None,
        };
        // Checked current, as the delivery checks it: a lapsed CA must not vouch for the collector even for a last
        // message. Such a collector cannot be verified, so it is not told.
        let ca = match row.tls_ca_pem.as_deref().filter(|_| protocol == SiemProtocol::SyslogTls) {
            Some(pem) => match CollectorCa::parse(Some(pem), instant(self.now())) {
                Ok(ca) => Some(ca),
                Err(unreadable) => {
                    tracing::warn!("The SIEM collector being left could not be read, so it was not told: {unreadable}");
                    return None;
                }
            },
            None => None,
        };
        Some(Collector { protocol, written: java::trim(written).to_owned(), endpoint, header, ca })
    }

    /// Sends `SIEM_EXPORT_STOPPED` to the collector being left, synchronously, and says in words for the audit entry
    /// whether it arrived.
    ///
    /// **Not through the outbox**, which reads the destination when the message leaves — by then the configuration no
    /// longer names this collector. **Not filtered by the minimum severity**: it is about the channel. **Best effort**:
    /// a collector that is down does not stop the export being switched off; the detail goes to the server log. The
    /// new destination is not named: the collector being left has no business learning where the feed went.
    async fn announce_stop(&self, previous: &Collector, redirected: bool, actor: &RequestActor) -> String {
        let message = if redirected {
            "The SIEM export was pointed at another collector: this one will receive no further events."
        } else {
            "The SIEM export was switched off: no further events will be sent until it is switched back on."
        };
        let stopped = CefEvent::builder(SecurityEventType::SiemExportStopped, instant(self.now()))
            .message(message)
            .user(actor.username.as_deref())
            .source_ip(actor.ip_address.as_deref())
            .action(AuditOperation::SettingUpdated.wire_name())
            .target(SINGLETON_ID.to_string().as_str())
            .user_agent(actor.user_agent.as_deref())
            .build();
        let sent = match stopped {
            Ok(event) => {
                self.transport.send(&previous.endpoint, previous.header.as_ref(), previous.ca.as_ref(), &event).await
            }
            Err(refused) => Err(SendError::failed("IllegalArgumentException", refused.0)),
        };
        match sent {
            Ok(()) => "; stop notice delivered to the previous collector".to_owned(),
            Err(failed) => {
                tracing::warn!(
                    "The SIEM stop notice to {} over {} was not delivered: {}",
                    previous.written,
                    previous.protocol.name(),
                    failed.message()
                );
                "; stop notice NOT delivered to the previous collector (the cause is in the server log)".to_owned()
            }
        }
    }

    /// Sends the health-check event, synchronously, over the protocol given — or the stored one when none is — so the
    /// button tests the transport the export will actually use.
    ///
    /// **An outcome, not the error.** The socket's own words — "Connection refused", "HTTP 404" — tell a closed port
    /// from a filtered one from a listening server: a scanner of whatever the policy lets the export reach. Three
    /// outcomes — delivered, refused by the policy, not delivered — and the detail goes to the server log.
    ///
    /// `tls_ca_pem`: absent tests the stored CA, blank the runtime's trust — so the button tests the CA on the form,
    /// saved or not. The header travels with a webhook only.
    pub async fn test_connection(
        &self,
        protocol: Option<&str>,
        endpoint_text: Option<&str>,
        auth_header: Option<&Secret>,
        tls_ca_pem: Option<&str>,
    ) -> Result<TestResult, SiemError> {
        if endpoint_text.is_none_or(java::is_blank) {
            return Ok(TestResult::refused("An endpoint is required."));
        }
        let mut stored: Option<Option<ConfigRow>> = None;
        let parsed = match protocol.filter(|value| !java::is_blank(value)) {
            Some(value) => match parse_protocol(value) {
                Ok(parsed) => parsed,
                Err(refused) => return Ok(TestResult::refused(refused.to_string())),
            },
            None => {
                let config = persistence::find(&self.db).await?;
                let known = config.as_ref().and_then(|config| SiemProtocol::by_name(Some(&config.protocol)));
                stored = Some(config);
                known.unwrap_or(SiemProtocol::Webhook)
            }
        };
        let destination = match endpoint::parse(parsed, endpoint_text) {
            Ok(destination) => destination,
            Err(refused) => return Ok(TestResult::refused(refused.0)),
        };
        let ca_text = match tls_ca_pem {
            Some(typed) => Some(typed.to_owned()),
            None => {
                let config = match stored {
                    Some(config) => config,
                    None => persistence::find(&self.db).await?,
                };
                config.and_then(|config| config.tls_ca_pem)
            }
        };
        let now = instant(self.now());
        let pinned = match ca_text.as_deref().filter(|pem| parsed == SiemProtocol::SyslogTls && !java::is_blank(pem)) {
            // The stored one is read as it was accepted; only a CA typed for this test is a paste.
            Some(pem) => {
                let read = if tls_ca_pem.is_some() {
                    CollectorCa::parse_pasted(Some(pem), now)
                } else {
                    CollectorCa::parse(Some(pem), now)
                };
                match read {
                    Ok(ca) => Some(ca),
                    Err(refused) => return Ok(TestResult::refused(refused.0)),
                }
            }
            None => None,
        };
        let ping = CefEvent::builder(SecurityEventType::PingTest, now).message("Vectispire SIEM health check").build();
        let sent = match ping {
            Ok(ping) => {
                let header = auth_header.filter(|_| parsed.carries_headers());
                self.transport.send(&destination, header, pinned.as_ref(), &ping).await
            }
            Err(refused) => Err(SendError::failed("IllegalArgumentException", refused.0)),
        };
        Ok(match sent {
            Ok(()) => TestResult {
                success: true,
                message: format!("Event delivered over {}.", parsed.name()),
                status_code: if parsed.carries_headers() { 200 } else { 0 },
            },
            Err(SendError::Refused(refused)) => {
                tracing::warn!("SIEM connection test refused by the outbound policy: {}", refused.0);
                TestResult::refused(REFUSED_BY_POLICY)
            }
            Err(failed) => {
                tracing::warn!("SIEM connection test over {} failed: {}", parsed.name(), failed.message());
                TestResult::refused(NOT_DELIVERED)
            }
        })
    }
}

fn invalid(refused: bounded_text::Refused) -> SiemError {
    SiemError::InvalidInput(refused.0)
}

fn parse_protocol(value: &str) -> Result<SiemProtocol, SiemError> {
    SiemProtocol::by_name(Some(value)).ok_or_else(|| {
        let names: Vec<&str> = SiemProtocol::ALL.iter().map(|protocol| protocol.name()).collect();
        SiemError::InvalidInput(format!(
            "Unknown SIEM protocol \"{}\". Expected one of: {}.",
            java::trim(value),
            names.join(", ")
        ))
    })
}

/// `SettingType.THRESHOLDS` by `equalsIgnoreCase` on the trimmed value — Java's simple case mappings, so `hıgh` (a
/// dotless i) is `HIGH` — stored in capitals, as the screen sends it.
fn threshold(value: &str) -> Result<String, SiemError> {
    let trimmed = java::trim(value);
    THRESHOLDS
        .iter()
        .find(|candidate| java::compare_ignore_case(candidate, trimmed).is_eq())
        .map(|candidate| candidate.to_ascii_uppercase())
        .ok_or_else(|| {
            SiemError::InvalidInput(format!(
                "Unknown minimum severity \"{trimmed}\". Expected one of: CRITICAL, HIGH, MEDIUM, LOW."
            ))
        })
}

/// A header value that can be sent, and whose ciphertext fits the column: visible ASCII and spaces only — a line break
/// in it is a header injection on every export — and bounded so that, encrypted, it stays inside V32's 2,048.
fn require_usable_header(header: &str) -> Result<(), SiemError> {
    bounded_text::within(header, MAX_AUTH_HEADER_LENGTH, "The authorization header").map_err(invalid)?;
    if !header.chars().all(|c| (' '..'\u{7f}').contains(&c)) {
        return Err(SiemError::InvalidInput(
            "The authorization header may hold printable ASCII only: no line break, no control or accented character."
                .to_owned(),
        ));
    }
    Ok(())
}
