//! The relay's handler for [`crate::events::TYPE`] — `SiemDelivery`: reads the queued event and sends it to the
//! collector configured *now*.
//!
//! **The destination is read at send time, not stored on the row**, for the reason the outbox gives about webhooks:
//! fixing a typo in the endpoint flushes the queue instead of losing it, and an endpoint written straight into the
//! database is still validated before anything is sent to it.
//!
//! **Gone, or retried.** A configuration switched off, an endpoint cleared or unreadable, a protocol this version does
//! not speak, a pinned CA that has lapsed: nothing about waiting brings them back, so the row is abandoned at once with
//! the reason ([`DeliveryError::Gone`]). A collector that does not answer, a row that cannot be read: retried on the
//! outbox's backoff, then abandoned, with the exception Java's delivery throws as the kind.
//!
//! Runs outside any transaction: the relay claims the row in one, sends, and settles it in another. A collector that
//! takes ten seconds to answer holds no lock.

use std::sync::Arc;

use uuid::Uuid;
use vectispire_cp_audit::Clock;
use vectispire_cp_crypto::Encryption;
use vectispire_cp_db::Db;
use vectispire_cp_outbox::{Delivery, DeliveryError, OutboxHandler};
use vectispire_domain::java;
use vectispire_domain::secret::Secret;
use vectispire_domain::siem::{CollectorCa, SiemProtocol, endpoint};

use crate::config::{AUTH_HEADER_CONTEXT, AUTH_HEADER_LABEL};
use crate::events::{QueuedEvent, TYPE, instant};
use crate::persistence;
use crate::transport::Transport;

/// The handler.
pub struct SiemDelivery {
    db: Db,
    transport: Arc<dyn Transport>,
    encryption: Arc<Encryption>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for SiemDelivery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SiemDelivery").finish_non_exhaustive()
    }
}

impl SiemDelivery {
    pub fn new(
        db: Db,
        transport: Arc<dyn Transport>,
        encryption: Arc<Encryption>,
        clock: Arc<dyn Clock>,
    ) -> SiemDelivery {
        SiemDelivery { db, transport, encryption, clock }
    }

    /// One message: sent, gone, or failed.
    pub async fn deliver_message(&self, message_id: Uuid, payload: &str) -> Result<(), DeliveryError> {
        let config = persistence::find(&self.db)
            .await
            .map_err(|error| DeliveryError::failed("DataAccessException", error.to_string()))?
            .filter(|config| config.enabled)
            .filter(|config| config.endpoint.as_deref().is_some_and(|endpoint| !java::is_blank(endpoint)))
            .ok_or_else(|| {
                DeliveryError::Gone(
                    "the SIEM export was switched off or its endpoint cleared after this event was queued".to_owned(),
                )
            })?;

        let protocol = SiemProtocol::by_name(Some(&config.protocol)).ok_or_else(|| {
            DeliveryError::Gone(format!(
                "the stored SIEM protocol \"{}\" is not one this version speaks",
                config.protocol
            ))
        })?;
        let destination = endpoint::parse(protocol, config.endpoint.as_deref()).map_err(|unreadable| {
            DeliveryError::Gone(format!("the stored SIEM endpoint is unusable for {}: {unreadable}", protocol.name()))
        })?;

        let event = QueuedEvent::read(payload)
            .and_then(|queued| queued.to_event(&message_id.to_string()))
            .map_err(|unreadable| DeliveryError::failed(unreadable.kind(), unreadable.to_string()))?;

        let header: Option<Secret> = if protocol.carries_headers() {
            Some(
                self.encryption
                    .read_secret(config.auth_header.as_deref().unwrap_or(""), AUTH_HEADER_CONTEXT, AUTH_HEADER_LABEL)
                    .await,
            )
        } else {
            None
        };
        let ca = self.pinned_ca(protocol, config.tls_ca_pem.as_deref())?;
        self.transport
            .send(&destination, header.as_ref(), ca.as_ref(), &event)
            .await
            .map_err(|failed| DeliveryError::failed(failed.kind(), failed.message()))
    }

    /// The collector CA, checked current *now*: the save checked it once, and a CA expires while its row sits
    /// unchanged. The TLS stack does not check a trust anchor's own dates, so without this an expired CA would go on
    /// being trusted — and a lapsed CA is a configuration to fix, which four hours of backoff do not do.
    fn pinned_ca(&self, protocol: SiemProtocol, stored: Option<&str>) -> Result<Option<CollectorCa>, DeliveryError> {
        let Some(stored) = stored.filter(|pem| protocol == SiemProtocol::SyslogTls && !java::is_blank(pem)) else {
            return Ok(None);
        };
        CollectorCa::parse(Some(stored), instant(self.clock.now()))
            .map(Some)
            .map_err(|unusable| DeliveryError::Gone(format!("the pinned SIEM collector CA is unusable: {unusable}")))
    }
}

impl OutboxHandler for SiemDelivery {
    fn message_type(&self) -> &str {
        TYPE
    }

    fn deliver<'a>(&'a self, message_id: Uuid, payload: &'a str) -> Delivery<'a> {
        Box::pin(self.deliver_message(message_id, payload))
    }
}
