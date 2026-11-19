//! An integration token's change of state, queued everywhere it is said (`TokenAlerts`), and the two outbox handlers
//! that say it: one message per channel (`TokenAlertDelivery`, `token_alert`) and the audit entry, through it the SIEM
//! event (`TokenAlertAudit`, `token_alert_audit`).
//!
//! **In the transaction that records the change as said**: an alert written after the commit would be lost to a stop
//! in between, and the next turn — finding the change already recorded — would never say it again. **The global
//! channels alone**, whatever the issue threshold says: a token is the installation's, not a team's.

use std::sync::Arc;

use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vectispire_cp_audit::{AuditLog, AuditOperation, Record};
use vectispire_cp_db::Tx;
use vectispire_cp_outbox::{Delivery, DeliveryError, Outbox, OutboxHandler, RaiseError, TokenAlertSink};
use vectispire_cp_settings::Integrations;
use vectispire_domain::notifications::TokenAlert;

use crate::channels::Channel;
use crate::gate;

/// `TokenAlertDelivery.TYPE`. Stored on every row: it must not move.
pub const DELIVERY_TYPE: &str = "token_alert";
/// `TokenAlertAudit.TYPE`.
pub const AUDIT_TYPE: &str = "token_alert_audit";

/// What `token_alert` queues: the channel's key and the alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Queued {
    pub channel: String,
    pub alert: TokenAlert,
}

/// `TokenAlerts`: the listener the owners' alerts reach.
pub struct TokenAlerts {
    outbox: Arc<Outbox>,
    channels: Vec<Arc<dyn Channel>>,
    integrations: Integrations,
}

impl std::fmt::Debug for TokenAlerts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenAlerts").finish_non_exhaustive()
    }
}

impl TokenAlerts {
    pub fn new(outbox: Arc<Outbox>, channels: Vec<Arc<dyn Channel>>, integrations: Integrations) -> TokenAlerts {
        TokenAlerts { outbox, channels, integrations }
    }
}

impl TokenAlertSink for TokenAlerts {
    fn changed<'a>(&'a self, tx: &'a mut Tx, alert: &'a TokenAlert) -> BoxFuture<'a, Result<(), RaiseError>> {
        Box::pin(async move {
            self.outbox.enqueue(tx, alert, AUDIT_TYPE, None).await?;
            // One row per destination: one channel down is retried on its own, without sending the others twice. A
            // channel switched off is queued nothing, as one without a destination is.
            for channel in &self.channels {
                if !channel.configured().await? || !gate::is_on(&self.integrations, channel.kind()).await? {
                    continue;
                }
                let queued = Queued { channel: channel.kind().wire_name().to_owned(), alert: alert.clone() };
                self.outbox.enqueue(tx, &queued, DELIVERY_TYPE, None).await?;
            }
            Ok(())
        })
    }
}

/// Delivers a queued alert to the channel its row names, reading the destination at the send.
pub struct TokenAlertDelivery {
    channels: Vec<Arc<dyn Channel>>,
}

impl std::fmt::Debug for TokenAlertDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenAlertDelivery").finish_non_exhaustive()
    }
}

impl TokenAlertDelivery {
    pub fn new(channels: Vec<Arc<dyn Channel>>) -> TokenAlertDelivery {
        TokenAlertDelivery { channels }
    }
}

impl OutboxHandler for TokenAlertDelivery {
    fn message_type(&self) -> &str {
        DELIVERY_TYPE
    }

    fn deliver<'a>(&'a self, message_id: Uuid, payload: &'a str) -> Delivery<'a> {
        Box::pin(async move {
            let queued: Queued = serde_json::from_str(payload).map_err(|_| {
                DeliveryError::failed(
                    "IllegalStateException",
                    format!("Token alert {message_id} has an unreadable payload"),
                )
            })?;
            // A row written by a newer version: retried then abandoned with its reason — never a silent skip.
            let channel =
                self.channels.iter().find(|channel| channel.kind().wire_name() == queued.channel).ok_or_else(|| {
                    DeliveryError::failed(
                        "IllegalStateException",
                        format!("Token alert {message_id} names an unknown channel: {}", queued.channel),
                    )
                })?;
            if !channel.configured().await.map_err(crate::internal::data_access)? {
                return Err(DeliveryError::Gone(format!("the {} channel is no longer configured", queued.channel)));
            }
            channel.deliver_alert(&queued.alert, &message_id.to_string()).await
        })
    }
}

/// Writes the alert's audit entry from the outbox, its operation the event's. **No actor**: nobody did this, and a
/// "system" user would put a person who does not exist into the trail an assessor reads.
#[derive(Debug, Clone)]
pub struct TokenAlertAudit {
    audit: Arc<AuditLog>,
}

impl TokenAlertAudit {
    pub fn new(audit: Arc<AuditLog>) -> TokenAlertAudit {
        TokenAlertAudit { audit }
    }
}

impl OutboxHandler for TokenAlertAudit {
    fn message_type(&self) -> &str {
        AUDIT_TYPE
    }

    fn deliver<'a>(&'a self, message_id: Uuid, payload: &'a str) -> Delivery<'a> {
        Box::pin(async move {
            let unreadable = || {
                DeliveryError::failed(
                    "IllegalStateException",
                    format!("Token alert audit {message_id} has an unreadable payload"),
                )
            };
            let alert: TokenAlert = serde_json::from_str(payload).map_err(|_| unreadable())?;
            let operation = AuditOperation::from_wire(alert.operation_name()).ok_or_else(unreadable)?;
            let record = Record {
                operation,
                resource_id: alert.reference.clone(),
                description: Some(format!("{} Delivery {message_id}.", alert.sentence())),
                user_id: None,
                ip_address: None,
                user_agent: None,
                signal: None,
            };
            // Fails when the entry cannot be written, so the relay retries rather than marking it sent.
            self.audit
                .append(record)
                .await
                .map_err(|failed| DeliveryError::failed("DataAccessException", failed.to_string()))
        })
    }
}
