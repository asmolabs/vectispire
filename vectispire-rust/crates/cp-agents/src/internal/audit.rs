//! Outbox handler for `agent_result_audit`.

use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
use vectispire_cp_audit::{AuditLog, AuditOperation, Record};
use vectispire_cp_outbox::{Delivery, DeliveryError, OutboxHandler};

pub const TYPE: &str = "agent_result_audit";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Queued {
    scan_id: i64,
    description: String,
    agent_name: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AgentResultAuditDelivery {
    audit: Arc<AuditLog>,
}

impl AgentResultAuditDelivery {
    pub fn new(audit: Arc<AuditLog>) -> Self {
        Self { audit }
    }
}

impl OutboxHandler for AgentResultAuditDelivery {
    fn message_type(&self) -> &str {
        TYPE
    }

    fn deliver<'a>(&'a self, message_id: Uuid, payload: &'a str) -> Delivery<'a> {
        Box::pin(async move {
            let queued: Queued = serde_json::from_str(payload).map_err(|_e| {
                DeliveryError::failed(
                    "IllegalStateException",
                    format!("Agent result audit {message_id} has an unreadable payload"),
                )
            })?;
            let record = Record {
                operation: AuditOperation::AgentResultSubmitted,
                resource_id: Some(queued.scan_id.to_string()),
                description: Some(format!("{} Delivery {message_id}.", queued.description)),
                user_id: Some(queued.agent_name),
                ip_address: queued.ip_address,
                user_agent: queued.user_agent,
                signal: None,
            };
            self.audit.record(record).await;
            Ok(())
        })
    }
}
