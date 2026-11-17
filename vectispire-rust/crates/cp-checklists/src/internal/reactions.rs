//! What the module does when the others act: a project deleted (`ChecklistPurge`), a repository scanned
//! (`AnswersFromEvidence`, which only queues), the queued answer delivered (`ChecklistAnswerDelivery`), and the hourly
//! offer of the weekly reminder (`ChecklistReminderTask`).

use std::sync::{Arc, OnceLock};

use uuid::Uuid;
use vectispire_cp_db::Tx;
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_maintenance::{MaintenanceTask, Sequence, TaskRun};
use vectispire_cp_outbox::{Delivery, DeliveryError, Outbox, OutboxHandler};
use vectispire_cp_settings::{Setting, Settings};
use vectispire_cp_targets::ProjectPurge;
use vectispire_cp_targets::deletion::PurgeError;

use crate::contact_service::ChecklistReminders;
use crate::error::ChecklistError;
use crate::persistence;
use crate::project_checklists::ProjectChecklists;

/// The outbox `message_type`. Stored on every row: it must not move.
pub const ANSWER_MESSAGE: &str = "checklist_answer";

/// `ChecklistPurge`: a project's checklists, answers, proofs, files, measurements, documents and contacts, in the
/// transaction that deletes it. The audit entries stay.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChecklistPurge;

impl ProjectPurge for ChecklistPurge {
    fn name(&self) -> (&'static str, &'static str) {
        ("checklists", "ChecklistPurge.purge")
    }

    fn purge<'a>(&'a self, tx: &'a mut Tx, project_id: i64) -> BoxFuture<'a, Result<(), PurgeError>> {
        Box::pin(async move { Ok(persistence::purge_project(tx, project_id).await?) })
    }
}

/// `AnswersFromEvidence`: a completed scan is new evidence about a repository, and the draft of its project is
/// answered again from it — **only queued**, in the scan's transaction (decision 0033). Nothing is queued while the
/// automatic answers are off; the delivery reads the setting again.
pub struct AnswersFromEvidence {
    pub outbox: Arc<Outbox>,
    pub settings: Arc<Settings>,
}

impl std::fmt::Debug for AnswersFromEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AnswersFromEvidence")
    }
}

impl AnswersFromEvidence {
    /// `queue`: the message, in `tx`, when the answers are on.
    pub async fn queue(&self, tx: &mut Tx, repository_id: i64) -> Result<(), PurgeError> {
        if self.settings.is_enabled(Setting::ChecklistAutoAnswer).await? {
            let payload = serde_json::json!({ "repository_id": repository_id });
            self.outbox.enqueue(tx, &payload, ANSWER_MESSAGE, None).await?;
        }
        Ok(())
    }
}

impl vectispire_cp_scanning::ports::RepositoryScanned for AnswersFromEvidence {
    fn scanned<'a>(
        &'a self,
        tx: &'a mut Tx,
        repository: i64,
        _scan: i64,
    ) -> BoxFuture<'a, Result<(), vectispire_cp_scanning::ports::PortError>> {
        Box::pin(async move { self.queue(tx, repository).await })
    }
}

/// `ChecklistAnswerDelivery`: answers, from the outbox, the measured lines of the draft of the project a repository
/// is filed in. At least once, and idempotent for it. **The service is looked up at delivery**: the outbox is built
/// with every handler before the services that audit through it exist.
#[derive(Debug, Clone, Default)]
pub struct ChecklistAnswerDelivery {
    pub checklists: Arc<OnceLock<Arc<ProjectChecklists>>>,
}

impl OutboxHandler for ChecklistAnswerDelivery {
    fn message_type(&self) -> &str {
        ANSWER_MESSAGE
    }

    fn deliver<'a>(&'a self, message_id: Uuid, payload: &'a str) -> Delivery<'a> {
        Box::pin(async move {
            let read: serde_json::Value = serde_json::from_str(payload).map_err(|_| {
                DeliveryError::failed(
                    "IllegalStateException",
                    format!("Checklist answer {message_id} has an unreadable payload"),
                )
            })?;
            // `JsonNode.canConvertToLong`: an integral number in range, or a decimal whose integral part is.
            let repository_id = match read.get("repository_id") {
                // The queue writes an integral id; a decimal is read by its integral digits, as `asLong` truncates.
                Some(serde_json::Value::Number(number)) => number.as_i64().or_else(|| {
                    let text = number.to_string();
                    text.split(['.', 'e', 'E']).next().and_then(|integral| integral.parse::<i64>().ok())
                }),
                _ => None,
            }
            .ok_or_else(|| {
                DeliveryError::failed(
                    "IllegalStateException",
                    format!("Checklist answer {message_id} names no repository"),
                )
            })?;
            let checklists = self.checklists.get().ok_or_else(|| {
                DeliveryError::failed("IllegalStateException", "The checklists' service is not composed")
            })?;
            checklists.answer_from_evidence(repository_id).await.map(|_| ()).map_err(|failure| match failure {
                ChecklistError::Conflict(conflict) => DeliveryError::failed("ChecklistConflict", conflict.message),
                other => DeliveryError::failed("RuntimeException", other.to_string()),
            })
        })
    }
}

/// `ChecklistReminderTask`: offered every hour; the service decides per recipient whether this week's has gone out.
#[derive(Debug, Clone)]
pub struct ChecklistReminderTask {
    pub reminders: Arc<ChecklistReminders>,
}

impl MaintenanceTask for ChecklistReminderTask {
    fn sequence(&self) -> Sequence {
        Sequence::ChecklistReminders
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            self.reminders.run_once().await;
            Ok(())
        })
    }
}
