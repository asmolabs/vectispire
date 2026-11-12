//! One-shot startup repair for withheld claims (`withheld-claim-repair`).
//!
//! Gives back, once per database, the attempts that withheld claims counted on scans never delivered.
//! Reproduces `core.agents.internal.WithheldClaimRepair` in Java.

use std::collections::BTreeSet;
use std::sync::Arc;
use time::OffsetDateTime;
use vectispire_cp_audit::{AuditLog, AuditLogQuery, AuditOperation, Record};
use vectispire_cp_db::{Db, Mode};
use vectispire_cp_maintenance::OneShotJobs;
use vectispire_cp_scanning::ScanCatalog;
use vectispire_cp_targets::Targets;

use crate::persistence::agents;

pub const JOB: &str = "withheld-claim-repair";

/// The audit column's width: past it the trail truncates.
const DESCRIPTION_LENGTH: usize = 255;

/// What one call did: nothing because it had run before, nothing because another instance claimed it,
/// or the scans whose attempts it gave back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    AlreadyDone,
    ClaimedElsewhere,
    Repaired(Vec<i64>),
}

#[derive(Debug, Clone)]
pub struct WithheldClaimRepair {
    db: Db,
    scans: ScanCatalog,
    targets: Arc<Targets>,
    trail: Arc<AuditLogQuery>,
    audit: Arc<AuditLog>,
    once: Arc<OneShotJobs>,
}

impl WithheldClaimRepair {
    pub fn new(
        db: Db,
        scans: ScanCatalog,
        targets: Arc<Targets>,
        trail: Arc<AuditLogQuery>,
        audit: Arc<AuditLog>,
        once: Arc<OneShotJobs>,
    ) -> Self {
        Self { db, scans, targets, trail, audit, once }
    }

    /// Runs the repair once. If an audit entry already exists, this repair never runs again.
    pub async fn repair_once(&self) -> Result<Outcome, Box<dyn std::error::Error + Send + Sync>> {
        if self.trail.count_since(AuditOperation::ScanAttemptsRepaired.wire_name(), OffsetDateTime::UNIX_EPOCH).await?
            > 0
        {
            return Ok(Outcome::AlreadyDone);
        }

        // Claimed and done in one transaction
        let mut tx = self.db.begin(Mode::ReadWrite).await?;
        if let Err(e) = self.once.claim(&mut tx, JOB).await {
            let _ = tx.rollback().await;
            if self.once.has_run(JOB).await? {
                return Ok(Outcome::ClaimedElsewhere);
            }
            return Err(Box::new(e));
        }

        let has_delegated = agents::has_delegated_mode(&mut tx).await?;
        let repaired = if has_delegated { self.refund_undelivered().await? } else { Vec::new() };

        tx.commit().await?;

        // Audit entry recorded after commit
        let record = Record::of(AuditOperation::ScanAttemptsRepaired, "scans", &describe(&repaired), None);
        self.audit.record(record).await;

        if !repaired.is_empty() {
            tracing::info!(
                "{} waiting scan(s) had the attempts of withheld claims given back: {}",
                repaired.len(),
                repaired.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(", ")
            );
        }

        Ok(Outcome::Repaired(repaired))
    }

    async fn refund_undelivered(&self) -> Result<Vec<i64>, Box<dyn std::error::Error + Send + Sync>> {
        let waiting = self.scans.waiting_with_attempts().await?;
        if waiting.is_empty() {
            return Ok(Vec::new());
        }

        let repo_ids: BTreeSet<i64> = waiting.iter().map(|s| s.repo_id).collect();
        let carrying = self.targets.carrying_credentials(&repo_ids).await?;

        let mut candidates: Vec<i64> =
            waiting.into_iter().filter(|scan| carrying.contains(&scan.repo_id)).map(|scan| scan.id).collect();
        candidates.sort_unstable();

        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        let candidate_strings: Vec<String> = candidates.iter().map(|id| id.to_string()).collect();
        let delivered =
            self.trail.resources_named(AuditOperation::AgentCredentialSent.wire_name(), &candidate_strings).await?;

        let undelivered: Vec<i64> = candidates.into_iter().filter(|id| !delivered.contains(&id.to_string())).collect();

        if undelivered.is_empty() {
            return Ok(Vec::new());
        }

        self.scans.refund_attempts(&undelivered).await?;
        Ok(undelivered)
    }
}

/// The entry, within the column's width: the count always, the identifiers as many as fit whole.
fn describe(repaired: &[i64]) -> String {
    if repaired.is_empty() {
        return "Upgrade check: no waiting scan carried attempts counted by claims withheld from a delegated agent."
            .to_string();
    }
    let mut text = format!(
        "Upgrade repair: attempts reset to 0 on {} waiting scan(s) whose credential no agent was ever handed, counted by withheld claims. Scans: ",
        repaired.len()
    );
    for (i, &id) in repaired.iter().enumerate() {
        let next = if i == 0 { format!("{id}") } else { format!(", {id}") };
        let remaining = repaired.len().saturating_sub(i.saturating_add(1));
        let rest = if remaining > 0 { format!(" and {remaining} more.") } else { ".".to_string() };
        let needed_len = text.len().saturating_add(next.len()).saturating_add(rest.len());
        if needed_len > DESCRIPTION_LENGTH {
            let left = repaired.len().saturating_sub(i);
            text.push_str(&format!(" and {left} more."));
            return text;
        }
        text.push_str(&next);
    }
    text.push('.');
    text
}
