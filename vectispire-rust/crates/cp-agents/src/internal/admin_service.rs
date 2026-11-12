//! Declaring, changing and removing agents, and reading what the queue looks like to them.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use vectispire_cp_access::credentials::CredentialService;
use vectispire_cp_audit::{AuditLog, AuditOperation, Record, RequestActor};
use vectispire_cp_db::Db;
use vectispire_cp_scanning::dispatcher::can_be_handed_credentials;
use vectispire_cp_scanning::{ClaimingAgent, ScanCatalog};
use vectispire_cp_targets::Targets;
use vectispire_domain::agent_labels;
use vectispire_domain::bounded_text;
use vectispire_domain::list_window::ListWindow;
use vectispire_protocol::CredentialsMode;
use vectispire_protocol::concurrency;

use crate::error::AgentError;
use crate::internal::backlog_task::{CredentialedBacklogProvider, Unserved};
use crate::persistence::StoreError;
use crate::persistence::agents::{self, AgentRow};

const ONLINE_TTL: Duration = Duration::seconds(120);
const KEY_NAME_PREFIX: &str = "Agent ";
const MAX_NAME_LENGTH: usize = 255 - KEY_NAME_PREFIX.len();
const MAX_DESCRIPTION_LENGTH: usize = 500;
const MAX_LABELS_LENGTH: usize = 255;
const SEALING_KEY_FORGOTTEN: &str =
    " Its sealing key is forgotten until it announces one signed with the key now pinned.";

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSummary {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub kind: String,
    pub enabled: bool,
    pub credentials_mode: String,
    pub labels: Option<String>,
    pub seals_credentials: bool,
    pub signs_results: bool,
    pub max_concurrent: u32,
    pub hostname: Option<String>,
    pub platform: Option<String>,
    pub version: Option<String>,
    pub contract_version: Option<String>,
    pub last_seen_at: Option<String>,
    pub online: bool,
    pub running_scans: i64,
}

#[derive(Debug, Clone, Default)]
pub struct Declaration {
    pub name: String,
    pub description: Option<String>,
    pub credentials_mode: Option<String>,
    pub labels: Option<String>,
    pub max_concurrent: Option<i32>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DeclaredAgent {
    pub id: Uuid,
    pub name: String,
    pub secret: String,
}

#[derive(Debug, Clone, Default)]
pub struct Change {
    pub enabled: Option<bool>,
    pub labels: Option<String>,
    pub max_concurrent: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct Changed {
    pub id: Uuid,
    pub enabled: bool,
    pub labels: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PinnedKey {
    pub id: Uuid,
    pub signs_results: bool,
    pub private_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Unroutable {
    pub label: String,
    pub queued: i64,
}

#[derive(Debug, Clone)]
pub struct RunningScan {
    pub scan_id: i64,
    pub target_type: String,
    pub target_id: i64,
    pub target_name: String,
    pub branch: Option<String>,
    pub agent_id: Option<String>,
    pub agent_name: Option<String>,
    pub claimed_at: OffsetDateTime,
    pub duration_seconds: i64,
    pub required_label: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PendingScan {
    pub scan_id: i64,
    pub target_type: String,
    pub target_id: i64,
    pub target_name: String,
    pub branch: Option<String>,
    pub required_label: Option<String>,
    pub queued_at: OffsetDateTime,
    pub wait_duration_seconds: i64,
    pub routable: bool,
    pub position_in_queue: i32,
}

#[derive(Debug, Clone, Default)]
pub struct QueueFigures {
    pub total_agents: i32,
    pub online_agents: i32,
    pub busy_agents: i32,
    pub idle_agents: i32,
    pub running_scans_count: i64,
    pub pending_scans_count: i64,
    pub scans_completed_24h: i64,
    pub avg_scan_duration_seconds: i64,
}

#[derive(Debug, Clone)]
pub struct Activity {
    pub running: Vec<RunningScan>,
    pub pending: Vec<PendingScan>,
    pub figures: QueueFigures,
}

#[derive(Clone)]
pub struct AgentAdministrationService {
    db: Db,
    credentials: Arc<CredentialService>,
    scans: Arc<ScanCatalog>,
    targets: Arc<Targets>,
    audit: Arc<AuditLog>,
    worker_labels: Vec<String>,
    worker_runs: bool,
}

impl std::fmt::Debug for AgentAdministrationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentAdministrationService").field("db", &self.db).finish_non_exhaustive()
    }
}

impl AgentAdministrationService {
    pub fn new(
        db: Db,
        credentials: Arc<CredentialService>,
        scans: Arc<ScanCatalog>,
        targets: Arc<Targets>,
        audit: Arc<AuditLog>,
        worker_labels: Vec<String>,
        worker_runs: bool,
    ) -> Self {
        Self { db, credentials, scans, targets, audit, worker_labels, worker_runs }
    }

    pub async fn list(&self, limit: Option<i64>, offset: Option<i64>) -> Result<Vec<AgentSummary>, AgentError> {
        let window = ListWindow::requested(limit, offset).map_err(AgentError::Invalid)?;
        let as_of = OffsetDateTime::now_utc();
        let running =
            self.scans.count_by_claimant("scanning").await.map_err(|e| AgentError::Unexpected(Box::new(e)))?;
        let fleet = agents::find_all_ordered(&self.db).await.map_err(AgentError::from)?;

        let page = window.map(|p| p.of(&fleet)).unwrap_or(fleet);
        Ok(page
            .into_iter()
            .map(|agent| {
                let online = is_online(&agent, as_of);
                let running_count = running.get(&agent.id.to_string()).copied().unwrap_or(0);
                let eff_max = concurrency::effective(agent.max_concurrent.map(i64::from));
                AgentSummary {
                    id: agent.id,
                    name: agent.name,
                    description: agent.description,
                    kind: agent.kind,
                    enabled: agent.enabled,
                    credentials_mode: agent.credentials_mode,
                    labels: agent.labels,
                    seals_credentials: agent.sealing_public_key.is_some(),
                    signs_results: agent.signing_public_key.is_some(),
                    max_concurrent: eff_max,
                    hostname: agent.hostname,
                    platform: agent.platform,
                    version: agent.version,
                    contract_version: agent.contract_version,
                    last_seen_at: agent.last_seen_at.map(vectispire_cp_audit::iso_instant),
                    online,
                    running_scans: running_count,
                }
            })
            .collect())
    }

    pub async fn declare(&self, declaration: Declaration, actor: &RequestActor) -> Result<DeclaredAgent, AgentError> {
        let name = declaration.name.trim();
        if name.is_empty() {
            return Err(AgentError::invalid("The agent's name is required."));
        }
        bounded_text::within(name, MAX_NAME_LENGTH, "The agent's name").map_err(AgentError::from)?;

        let description =
            bounded_text::optional(declaration.description.as_deref(), MAX_DESCRIPTION_LENGTH, "The description")
                .map_err(AgentError::from)?;

        let labels = joined_labels(declaration.labels.as_deref())?;

        let max_concurrent = match declaration.max_concurrent {
            Some(requested) => bounded_concurrency(requested)?,
            None => concurrency::DEFAULT as i32,
        };

        let mode = match declaration.credentials_mode.as_deref() {
            None => CredentialsMode::Local,
            Some(raw) if raw.trim().is_empty() => CredentialsMode::Local,
            Some(raw) => CredentialsMode::by_wire_name(Some(raw.trim()))
                .ok_or_else(|| AgentError::invalid(format!("Unknown credentials mode: \"{}\".", raw.trim())))?,
        };

        let key_name = format!("{KEY_NAME_PREFIX}{name}");
        let (api_key_id, secret) =
            self.credentials.issue_agent_key(&key_name).await.map_err(|e| AgentError::Unexpected(Box::new(e)))?;

        let now = OffsetDateTime::now_utc();
        let agent_row = AgentRow {
            id: Uuid::new_v4(),
            name: name.to_owned(),
            description,
            kind: "remote".to_owned(),
            labels,
            credentials_mode: mode.wire_name().to_owned(),
            enabled: true,
            max_concurrent: Some(max_concurrent),
            api_key_id: Some(api_key_id),
            hostname: None,
            platform: None,
            version: None,
            scanner_engine: None,
            capabilities: None,
            contract_version: None,
            sealing_public_key: None,
            sealing_key_generation: None,
            signing_public_key: None,
            last_seen_at: None,
            created_at: now,
        };

        let mut tx = crate::persistence::write(&self.db).await.map_err(AgentError::from)?;
        agents::insert(&mut tx, &agent_row).await.map_err(AgentError::from)?;
        tx.commit().await.map_err(StoreError::from)?;

        self.record_audit(
            actor,
            AuditOperation::AgentUpdated,
            &agent_row.id.to_string(),
            &format!("Agent declared: {} ({})", name, mode.wire_name()),
        )
        .await;

        Ok(DeclaredAgent { id: agent_row.id, name: agent_row.name, secret: secret.expose().to_owned() })
    }

    pub async fn change(&self, id: Uuid, change: Change, actor: &RequestActor) -> Result<Changed, AgentError> {
        let agent = agents::find_by_id(&self.db, id)
            .await
            .map_err(AgentError::from)?
            .ok_or_else(|| AgentError::not_found("Agent not found."))?;

        let enabled = change.enabled.unwrap_or(agent.enabled);
        let labels = match change.labels {
            Some(ref l) => joined_labels(Some(l))?,
            None => agent.labels.clone(),
        };
        let max_concurrent = match change.max_concurrent {
            Some(requested) => Some(bounded_concurrency(requested)?),
            None => agent.max_concurrent,
        };

        if labels != agent.labels {
            self.record_audit(
                actor,
                AuditOperation::AgentUpdated,
                &id.to_string(),
                &format!(
                    "Agent {} labels: {} (previously {})",
                    agent.name,
                    labels.as_deref().unwrap_or("none"),
                    agent.labels.as_deref().unwrap_or("none")
                ),
            )
            .await;
        }

        if enabled != agent.enabled {
            self.record_audit(
                actor,
                AuditOperation::AgentUpdated,
                &id.to_string(),
                &format!("Agent {} {}", agent.name, if enabled { "re-enabled" } else { "disabled" }),
            )
            .await;
        }

        if max_concurrent != agent.max_concurrent {
            let eff_prev = concurrency::effective(agent.max_concurrent.map(i64::from));
            self.record_audit(
                actor,
                AuditOperation::AgentUpdated,
                &id.to_string(),
                &format!(
                    "Agent {} max concurrent scans: {} (previously {})",
                    agent.name,
                    max_concurrent.unwrap_or(concurrency::DEFAULT as i32),
                    eff_prev
                ),
            )
            .await;
        }

        let updated_row = AgentRow { enabled, labels: labels.clone(), max_concurrent, ..agent };

        let mut tx = crate::persistence::write(&self.db).await.map_err(AgentError::from)?;
        agents::update(&mut tx, &updated_row).await.map_err(AgentError::from)?;
        tx.commit().await.map_err(StoreError::from)?;

        Ok(Changed { id, enabled, labels })
    }

    pub async fn pin_signing_key(
        &self,
        id: Uuid,
        public_key: Option<&str>,
        actor: &RequestActor,
    ) -> Result<PinnedKey, AgentError> {
        let agent = agents::find_by_id(&self.db, id)
            .await
            .map_err(AgentError::from)?
            .ok_or_else(|| AgentError::not_found("Agent not found."))?;

        let supplied = public_key.unwrap_or("").trim();

        if supplied.is_empty() {
            let mut tx = crate::persistence::write(&self.db).await.map_err(AgentError::from)?;
            agents::pin_signing_key(&mut tx, id, None).await.map_err(AgentError::from)?;
            agents::forget_sealing_key(&mut tx, id).await.map_err(AgentError::from)?;
            tx.commit().await.map_err(StoreError::from)?;

            self.record_audit(
                actor,
                AuditOperation::AgentSigningKeyPinned,
                &id.to_string(),
                &format!(
                    "Result-signing key removed for agent {}: its results are accepted on its API key alone, and it is handed no delegated credential until a key is pinned again.{}",
                    agent.name, SEALING_KEY_FORGOTTEN
                ),
            )
            .await;
            return Ok(PinnedKey { id, signs_results: false, private_key: None });
        }

        if supplied == "generate" {
            let (public_key, private_key) = vectispire_crypto::generate_signing_key_pair();

            let mut tx = crate::persistence::write(&self.db).await.map_err(AgentError::from)?;
            agents::pin_signing_key(&mut tx, id, Some(&public_key)).await.map_err(AgentError::from)?;
            agents::forget_sealing_key(&mut tx, id).await.map_err(AgentError::from)?;
            tx.commit().await.map_err(StoreError::from)?;

            self.record_audit(
                actor,
                AuditOperation::AgentSigningKeyPinned,
                &id.to_string(),
                &format!("Result-signing key generated and pinned for agent {}.{}", agent.name, SEALING_KEY_FORGOTTEN),
            )
            .await;
            return Ok(PinnedKey { id, signs_results: true, private_key: Some(private_key) });
        }

        if !is_usable_ed25519_public_key(supplied) {
            return Err(AgentError::invalid(
                "That is not an Ed25519 public key: 32 bytes of base64 are expected. Send \"generate\" \
                 to have one made here instead.",
            ));
        }

        let mut tx = crate::persistence::write(&self.db).await.map_err(AgentError::from)?;
        agents::pin_signing_key(&mut tx, id, Some(supplied)).await.map_err(AgentError::from)?;
        agents::forget_sealing_key(&mut tx, id).await.map_err(AgentError::from)?;
        tx.commit().await.map_err(StoreError::from)?;

        self.record_audit(
            actor,
            AuditOperation::AgentSigningKeyPinned,
            &id.to_string(),
            &format!("Result-signing key pinned for agent {}.{}", agent.name, SEALING_KEY_FORGOTTEN),
        )
        .await;

        Ok(PinnedKey { id, signs_results: true, private_key: None })
    }

    pub async fn reset_sealing_key(&self, id: Uuid, actor: &RequestActor) -> Result<(), AgentError> {
        let agent = agents::find_by_id(&self.db, id)
            .await
            .map_err(AgentError::from)?
            .ok_or_else(|| AgentError::not_found("Agent not found."))?;

        let mut tx = crate::persistence::write(&self.db).await.map_err(AgentError::from)?;
        agents::forget_sealing_key(&mut tx, id).await.map_err(AgentError::from)?;
        tx.commit().await.map_err(StoreError::from)?;

        self.record_audit(
            actor,
            AuditOperation::AgentSealingKeyReset,
            &id.to_string(),
            &format!(
                "Sealing key reset for agent {}: no delegated credential is handed to it until it announces a new key signed with its pinned signing key.",
                agent.name
            ),
        )
        .await;

        Ok(())
    }

    pub async fn remove(&self, id: Uuid, actor: &RequestActor) -> Result<(), AgentError> {
        let agent = agents::find_by_id(&self.db, id)
            .await
            .map_err(AgentError::from)?
            .ok_or_else(|| AgentError::not_found("Agent not found."))?;

        let running = self
            .scans
            .count_claimed_by("scanning", &id.to_string())
            .await
            .map_err(|e| AgentError::Unexpected(Box::new(e)))?;
        if running > 0 {
            return Err(AgentError::invalid(format!(
                "This agent is running {running} scan(s). Disable it and wait for it to finish."
            )));
        }

        let mut tx = crate::persistence::write(&self.db).await.map_err(AgentError::from)?;
        agents::delete_by_id(&mut tx, id).await.map_err(AgentError::from)?;
        tx.commit().await.map_err(StoreError::from)?;

        if let Some(key_id) = agent.api_key_id {
            let _ = self.credentials.revoke_key(key_id).await;
        }

        self.record_audit(
            actor,
            AuditOperation::AgentUpdated,
            &id.to_string(),
            &format!("Agent deleted: {}", agent.name),
        )
        .await;

        Ok(())
    }

    pub async fn activity(&self) -> Result<Activity, AgentError> {
        let as_of = OffsetDateTime::now_utc();
        let last24h = as_of.checked_sub(Duration::hours(24)).unwrap_or(as_of);

        let all_agents = agents::find_all_ordered(&self.db).await.map_err(AgentError::from)?;
        let mut agent_names = HashMap::new();
        let mut active_agent_labels = HashSet::new();
        let mut online_count: i32 = 0;

        for a in &all_agents {
            agent_names.insert(a.id.to_string(), a.name.clone());
            if is_online(a, as_of) {
                online_count = online_count.saturating_add(1);
                if a.enabled {
                    for label in agent_labels::parse(a.labels.as_deref()) {
                        active_agent_labels.insert(label);
                    }
                }
            }
        }
        for l in &self.worker_labels {
            active_agent_labels.insert(l.clone());
        }

        let mut repo_names = HashMap::new();
        for r in self.targets.catalog_repositories().await.map_err(AgentError::from)? {
            let name = if let Some(ref n) = r.name {
                if !n.trim().is_empty() { n.clone() } else { format!("Repo #{}", r.id) }
            } else {
                format!("Repo #{}", r.id)
            };
            repo_names.insert(r.id, name);
        }

        let mut container_names = HashMap::new();
        for c in self.targets.catalog_containers().await.map_err(AgentError::from)? {
            let tag_part = if c.tag.is_empty() { String::new() } else { format!(":{}", c.tag) };
            container_names.insert(c.id, format!("{}{}", c.image_name, tag_part));
        }

        let active_scans = self
            .scans
            .with_status_oldest_first(["scanning", "pending"])
            .await
            .map_err(|e| AgentError::Unexpected(Box::new(e)))?;

        let mut running_items = Vec::new();
        let mut pending_items = Vec::new();
        let mut busy_agent_ids = HashSet::new();
        let mut pending_pos = 1;

        for scan in active_scans {
            let (target_type, target_id, target_name) = if let Some(repo_id) = scan.repo_id {
                let name = repo_names.get(&repo_id).cloned().unwrap_or_else(|| format!("Repository #{repo_id}"));
                ("repository".to_owned(), repo_id, name)
            } else if let Some(container_id) = scan.container_id {
                let name =
                    container_names.get(&container_id).cloned().unwrap_or_else(|| format!("Container #{container_id}"));
                ("container".to_owned(), container_id, name)
            } else {
                ("unknown".to_owned(), 0, "Unknown Target".to_owned())
            };

            let branch = if scan.branch.is_empty() { None } else { Some(scan.branch.clone()) };

            if scan.status == "scanning" {
                let agent_id = scan.claimed_by.clone();
                let agent_name = match agent_id.as_deref() {
                    Some(id) if id.eq_ignore_ascii_case("worker") || id.eq_ignore_ascii_case("built-in") => {
                        Some("Built-in Worker".to_owned())
                    }
                    Some(id) => Some(agent_names.get(id).cloned().unwrap_or_else(|| format!("Agent {id}"))),
                    None => Some("Unknown Worker".to_owned()),
                };

                if let Some(ref id) = agent_id {
                    busy_agent_ids.insert(id.clone());
                }

                let claimed_time = scan.claimed_at.unwrap_or(scan.created_at);
                #[allow(clippy::arithmetic_side_effects)]
                let duration_sec = (as_of - claimed_time).whole_seconds().max(0);

                running_items.push(RunningScan {
                    scan_id: scan.id,
                    target_type,
                    target_id,
                    target_name,
                    branch,
                    agent_id,
                    agent_name,
                    claimed_at: claimed_time,
                    duration_seconds: duration_sec,
                    required_label: scan.required_agent_label,
                });
            } else if scan.status == "pending" {
                let is_routable = match scan.required_agent_label.as_deref() {
                    None => true,
                    Some(req) if req.trim().is_empty() => true,
                    Some(req) => active_agent_labels.contains(req),
                };

                #[allow(clippy::arithmetic_side_effects)]
                let wait_sec = (as_of - scan.created_at).whole_seconds().max(0);

                pending_items.push(PendingScan {
                    scan_id: scan.id,
                    target_type,
                    target_id,
                    target_name,
                    branch,
                    required_label: scan.required_agent_label,
                    queued_at: scan.created_at,
                    wait_duration_seconds: wait_sec,
                    routable: is_routable,
                    position_in_queue: pending_pos,
                });
                pending_pos = pending_pos.saturating_add(1);
            }
        }

        let mut busy_count: i32 = 0;
        for a in &all_agents {
            if busy_agent_ids.contains(&a.id.to_string()) && is_online(a, as_of) {
                busy_count = busy_count.saturating_add(1);
            }
        }
        let idle_count = online_count.saturating_sub(busy_count);

        let completed24h =
            self.scans.count_since("completed", last24h).await.map_err(|e| AgentError::Unexpected(Box::new(e)))?;
        let avg_dur_ms = self
            .scans
            .average_duration_since("completed", last24h)
            .await
            .map_err(|e| AgentError::Unexpected(Box::new(e)))?;
        #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
        let avg_dur_sec = avg_dur_ms.map(|ms| (ms / 1000.0).round() as i64).unwrap_or(0);

        let figures = QueueFigures {
            total_agents: i32::try_from(all_agents.len()).unwrap_or(i32::MAX),
            online_agents: online_count,
            busy_agents: busy_count,
            idle_agents: idle_count,
            running_scans_count: i64::try_from(running_items.len()).unwrap_or(i64::MAX),
            pending_scans_count: i64::try_from(pending_items.len()).unwrap_or(i64::MAX),
            scans_completed_24h: completed24h,
            avg_scan_duration_seconds: avg_dur_sec,
        };

        Ok(Activity { running: running_items, pending: pending_items, figures })
    }

    pub async fn unroutable(&self) -> Result<Vec<Unroutable>, AgentError> {
        let mut served = HashSet::new();
        for agent in agents::find_enabled(&self.db).await.map_err(AgentError::from)? {
            for label in agent_labels::parse(agent.labels.as_deref()) {
                served.insert(label);
            }
        }
        for label in &self.worker_labels {
            served.insert(label.clone());
        }

        let pending_counts =
            self.scans.count_by_required_label("pending").await.map_err(|e| AgentError::Unexpected(Box::new(e)))?;
        let mut unroutable = Vec::new();
        for (label, count) in pending_counts {
            if !served.contains(&label) {
                unroutable.push(Unroutable { label, queued: count });
            }
        }
        Ok(unroutable)
    }

    pub async fn unserved_backlog(&self) -> Result<Unserved, AgentError> {
        let enabled = agents::find_enabled(&self.db).await.map_err(AgentError::from)?;
        let capable: Vec<&AgentRow> = enabled.iter().filter(|a| can_be_handed(a)).collect();
        let worker_runs = self.worker_runs;

        let mut served_labels = HashSet::new();
        for l in &self.worker_labels {
            served_labels.insert(l.clone());
        }
        for a in &capable {
            for l in agent_labels::parse(a.labels.as_deref()) {
                served_labels.insert(l);
            }
        }

        let any_capable = worker_runs || !capable.is_empty();
        let waiting = self.scans.waiting_repositories().await.map_err(|e| AgentError::Unexpected(Box::new(e)))?;

        let unserved_scans: Vec<_> = waiting
            .into_iter()
            .filter(|row| !any_capable || row.required_label.as_ref().is_some_and(|l| !served_labels.contains(l)))
            .collect();

        if unserved_scans.is_empty() {
            return Ok(Unserved { scans: 0, labels: Vec::new(), kept_agents: Vec::new() });
        }

        let repo_ids: BTreeSet<i64> = unserved_scans.iter().map(|s| s.repo_id).collect();
        let carrying = self.targets.carrying_credentials(&repo_ids).await.map_err(AgentError::from)?;

        let needing: Vec<_> = unserved_scans.into_iter().filter(|s| carrying.contains(&s.repo_id)).collect();
        if needing.is_empty() {
            return Ok(Unserved { scans: 0, labels: Vec::new(), kept_agents: Vec::new() });
        }

        let mut labels_set = BTreeSet::new();
        for row in &needing {
            labels_set.insert(row.required_label.clone().unwrap_or_default());
        }

        let mut kept = Vec::new();
        for a in &enabled {
            if !can_be_handed(a) {
                let a_labels = agent_labels::parse(a.labels.as_deref());
                let serves = needing.iter().any(|r| r.required_label.as_ref().is_none_or(|l| a_labels.contains(l)));
                if serves {
                    kept.push(a.name.clone());
                }
            }
        }
        kept.sort();

        let total_scans: i64 = needing.iter().map(|s| s.scans).sum();
        Ok(Unserved { scans: total_scans, labels: labels_set.into_iter().collect(), kept_agents: kept })
    }

    async fn record_audit(&self, actor: &RequestActor, op: AuditOperation, resource_id: &str, description: &str) {
        self.audit
            .record(Record {
                operation: op,
                resource_id: Some(resource_id.to_owned()),
                description: Some(description.to_owned()),
                user_id: actor.username.clone(),
                ip_address: actor.ip_address.clone(),
                user_agent: actor.user_agent.clone(),
                signal: None,
            })
            .await;
    }
}

impl CredentialedBacklogProvider for AgentAdministrationService {
    fn unserved(
        &self,
    ) -> vectispire_cp_http::credentials::BoxFuture<'_, Result<Unserved, Box<dyn std::error::Error + Send + Sync>>>
    {
        Box::pin(async move {
            self.unserved_backlog().await.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        })
    }
}

#[allow(clippy::arithmetic_side_effects)]
fn is_online(agent: &AgentRow, as_of: OffsetDateTime) -> bool {
    agent.last_seen_at.is_some_and(|seen| as_of - seen < ONLINE_TTL)
}

fn bounded_concurrency(requested: i32) -> Result<i32, AgentError> {
    if requested < concurrency::MIN as i32 || requested > concurrency::MAX as i32 {
        return Err(AgentError::invalid(format!(
            "max_concurrent must be between {} and {}, not {}.",
            concurrency::MIN,
            concurrency::MAX,
            requested
        )));
    }
    Ok(requested)
}

fn joined_labels(raw: Option<&str>) -> Result<Option<String>, AgentError> {
    let parsed = agent_labels::parse(raw);
    if parsed.is_empty() {
        return Ok(None);
    }
    let joined = parsed.join(",");
    let bounded = bounded_text::within(&joined, MAX_LABELS_LENGTH, "The labels").map_err(AgentError::from)?;
    Ok(Some(bounded.to_owned()))
}

fn is_usable_ed25519_public_key(value: &str) -> bool {
    vectispire_crypto::is_valid_signing_public_key(value)
}

fn can_be_handed(agent: &AgentRow) -> bool {
    let ca = ClaimingAgent {
        id: agent.id,
        name: Some(agent.name.clone()),
        credentials_mode: Some(agent.credentials_mode.clone()),
        sealing_public_key: agent.sealing_public_key.clone(),
        signing_public_key: agent.signing_public_key.clone(),
        labels: agent.labels.clone(),
        max_concurrent: agent.max_concurrent.map(i64::from),
    };
    can_be_handed_credentials(&ca)
}
