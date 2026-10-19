//! Protocol service: hello handshake, heartbeat, sealing key announcement, result submission, failure reporting.

use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use vectispire_cp_audit::{AuditLog, AuditOperation, Record, RequestActor};
use vectispire_cp_db::Db;
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_outbox::Outbox;
use vectispire_cp_scanning::dispatcher::{Alongside, ClaimingAgent, ScanDispatcher};
use vectispire_cp_scanning::ports::{PortError, ScanRuleSets};
use vectispire_crypto::{is_usable_sealing_key, verify_failure, verify_result, verify_sealing_key};
use vectispire_domain::bounded_text;
use vectispire_protocol::concurrency;
use vectispire_protocol::server::refusals;
use vectispire_protocol::server::{
    FailureAnswer, FailureReport, HelloAnswer, HelloRequest, RouteRefusal, SealingKeyRequest, contract_is_compatible,
    iso_instant,
};
use vectispire_protocol::{ScanArtifacts, StoredFile, failure_reason};

use crate::persistence::agents::{self, AgentRow, HeartbeatData};

const SEEN_GRANULARITY: Duration = Duration::seconds(15);

pub trait AgentPluginProvider: Send + Sync {
    fn manifest<'a>(
        &'a self,
        id: &'a str,
        digest: &'a str,
    ) -> BoxFuture<'a, Result<Option<serde_json::Value>, PortError>>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoAgentPlugins;

impl AgentPluginProvider for NoAgentPlugins {
    fn manifest<'a>(
        &'a self,
        _id: &'a str,
        _digest: &'a str,
    ) -> BoxFuture<'a, Result<Option<serde_json::Value>, PortError>> {
        Box::pin(async { Ok(None) })
    }
}

#[derive(Clone)]
pub struct AgentProtocolService {
    db: Db,
    dispatcher: Arc<ScanDispatcher>,
    audit: Arc<AuditLog>,
    outbox: Arc<Outbox>,
    rule_sets: Arc<dyn ScanRuleSets>,
    plugins: Arc<dyn AgentPluginProvider>,
}

impl std::fmt::Debug for AgentProtocolService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentProtocolService").field("db", &self.db).finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct AuthenticatedAgent {
    pub id: Uuid,
    pub name: String,
    pub max_concurrent: Option<i32>,
    pub credentials_mode: String,
    pub enabled: bool,
    pub sealing_public_key: Option<String>,
    pub sealing_key_generation: Option<i64>,
    pub signing_public_key: Option<String>,
    pub labels: Option<String>,
    pub last_seen_at: Option<OffsetDateTime>,
}

impl From<&AgentRow> for AuthenticatedAgent {
    fn from(row: &AgentRow) -> Self {
        Self {
            id: row.id,
            name: row.name.clone(),
            max_concurrent: row.max_concurrent,
            credentials_mode: row.credentials_mode.clone(),
            enabled: row.enabled,
            sealing_public_key: row.sealing_public_key.clone(),
            sealing_key_generation: row.sealing_key_generation,
            signing_public_key: row.signing_public_key.clone(),
            labels: row.labels.clone(),
            last_seen_at: row.last_seen_at,
        }
    }
}

impl AgentProtocolService {
    pub fn new(
        db: Db,
        dispatcher: Arc<ScanDispatcher>,
        audit: Arc<AuditLog>,
        outbox: Arc<Outbox>,
        rule_sets: Arc<dyn ScanRuleSets>,
        plugins: Arc<dyn AgentPluginProvider>,
    ) -> Self {
        Self { db, dispatcher, audit, outbox, rule_sets, plugins }
    }

    pub async fn authenticate_agent(&self, agent_name_or_actor: &str) -> Result<AuthenticatedAgent, RouteRefusal> {
        let name = agent_name_or_actor.strip_prefix("agent:").unwrap_or(agent_name_or_actor);
        let row = agents::find_by_name(&self.db, name)
            .await
            .map_err(|_| refusals::not_an_agent())?
            .ok_or_else(refusals::not_an_agent)?;
        if !row.enabled {
            return Err(refusals::disabled(&row.name));
        }
        Ok(AuthenticatedAgent::from(&row))
    }

    pub fn admits(&self, agent: &AuthenticatedAgent) -> bool {
        agent.enabled
    }

    pub async fn hello(&self, agent: &AuthenticatedAgent, req: &HelloRequest) -> Result<HelloAnswer, RouteRefusal> {
        let announced = req.contract_version.as_deref();
        if !contract_is_compatible(announced) {
            return Err(refusals::incompatible_contract(announced));
        }

        let now = OffsetDateTime::now_utc();
        let hostname = bounded_text::clip(req.hostname.as_deref(), 255);
        let platform = bounded_text::clip(req.platform.as_deref(), 255);
        let version = bounded_text::clip(req.version.as_deref(), 50);
        let scanner_engine = bounded_text::clip(req.scanner_engine.as_deref(), 50);
        let capabilities = bounded_text::clip(req.capabilities.as_deref(), bounded_text::TEXT_MAX);
        let trimmed_contract = announced.map(str::trim);

        let data = HeartbeatData {
            hostname,
            platform,
            version,
            scanner_engine,
            capabilities,
            contract_version: trimmed_contract,
        };

        let _ = agents::record_heartbeat(&self.db, agent.id, now, &data).await;

        let eff_max = concurrency::effective(agent.max_concurrent.map(i64::from)) as i32;
        Ok(HelloAnswer::new(Some(agent.id), Some(agent.name.clone()), eff_max, Some(agent.credentials_mode.clone())))
    }

    pub async fn heard_from(&self, agent: &AuthenticatedAgent) {
        let now = OffsetDateTime::now_utc();
        let stale_before = now.checked_sub(SEEN_GRANULARITY).unwrap_or(now);
        if agent.last_seen_at.is_some_and(|last| last >= stale_before) {
            return;
        }
        let _ = agents::record_seen(&self.db, agent.id, now, stale_before).await;
    }

    pub async fn renew_lease(&self, agent: &AuthenticatedAgent, scan_id: i64) -> Result<bool, PortError> {
        self.heard_from(agent).await;
        let claiming = to_claiming_agent(agent);
        self.dispatcher.renew_agent_lease(scan_id, &claiming).await
    }

    pub async fn announce_sealing_key(
        &self,
        agent: &AuthenticatedAgent,
        req: &SealingKeyRequest,
        origin: &RequestActor,
    ) -> Result<(), RouteRefusal> {
        let key = req.public_key.as_deref().map(str::trim).filter(|k| !k.is_empty());
        let generation = req.generation;
        let signature = req.signature.as_deref().unwrap_or("").trim();

        let (Some(key), Some(gen_num)) = (key, generation) else {
            return Err(refusals::sealing_key_unreadable());
        };

        if gen_num <= 0 || !is_usable_sealing_key(key) {
            return Err(refusals::sealing_key_unreadable());
        }

        let pinned = agent.signing_public_key.as_deref().map(str::trim).filter(|p| !p.is_empty());
        let Some(pinned) = pinned else {
            return Err(refusals::sealing_key_not_pinned(&agent.name));
        };

        if !verify_sealing_key(pinned, agent.id, gen_num, key, signature) {
            self.record_audit(
                origin,
                AuditOperation::AgentSealingKeyRefused,
                &agent.id.to_string(),
                &format!(
                    "Sealing key refused for agent \"{}\": its signature does not verify against the pinned signing key. No credential is sealed for it.",
                    agent.name
                ),
            )
            .await;
            return Err(refusals::sealing_key_not_verified(&agent.name));
        }

        let accepted = agents::accept_sealing_key(&self.db, agent.id, key, gen_num)
            .await
            .map_err(|_| refusals::sealing_key_unreadable())?;

        if !accepted {
            self.record_audit(
                origin,
                AuditOperation::AgentSealingKeyRefused,
                &agent.id.to_string(),
                &format!(
                    "Sealing key refused for agent \"{}\": generation {} is not newer than the key already accepted. No credential is sealed for it.",
                    agent.name, gen_num
                ),
            )
            .await;
            return Err(refusals::sealing_key_stale(&agent.name));
        }

        let rotated = agent.sealing_public_key.as_deref() != Some(key);
        if rotated {
            self.record_audit(
                origin,
                AuditOperation::AgentSealingKeyAccepted,
                &agent.id.to_string(),
                &format!(
                    "Sealing key accepted for agent \"{}\", signed with its pinned key (generation {}). Credentials delegated to it are sealed for this key.",
                    agent.name, gen_num
                ),
            )
            .await;
        }

        Ok(())
    }

    pub async fn submit_result(
        &self,
        agent: &AuthenticatedAgent,
        scan_id: i64,
        body: &[u8],
        signature: Option<&str>,
        origin: &RequestActor,
    ) -> Result<(), RouteRefusal> {
        let pinned = agent.signing_public_key.as_deref().map(str::trim).filter(|p| !p.is_empty());
        if let Some(pinned) = pinned {
            let sig = signature.unwrap_or("").trim();
            if !verify_result(pinned, scan_id, body, sig) {
                let desc = if sig.is_empty() {
                    format!(
                        "Result submitted with no attestation by agent \"{}\", whose signing key is pinned.",
                        agent.name
                    )
                } else {
                    format!(
                        "Result submitted with an attestation that does not verify by agent \"{}\", whose signing key is pinned.",
                        agent.name
                    )
                };
                self.record_audit(origin, AuditOperation::AgentResultRefused, &scan_id.to_string(), &desc).await;
                return Err(refusals::result_not_attested(&agent.name));
            }
        }

        let artifacts = match ScanArtifacts::read(body) {
            Ok(artifacts) => artifacts,
            _ => return Err(refusals::result_unreadable()),
        };

        let now = OffsetDateTime::now_utc();
        let attestation_note = if pinned.is_none() { " (not attested)." } else { ", attestation verified." };
        let description = format!(
            "Result accepted from agent \"{}\" at {}{}",
            agent.name,
            iso_instant(vectispire_domain::instant::Instant {
                epoch_second: now.unix_timestamp(),
                nano: now.nanosecond(),
            }),
            attestation_note
        );

        let alongside = AuditAlongside {
            outbox: &self.outbox,
            scan_id,
            description,
            agent_name: agent.name.clone(),
            ip_address: origin.ip_address.clone(),
            user_agent: origin.user_agent.clone(),
        };

        let claiming = to_claiming_agent(agent);
        let accepted = self
            .dispatcher
            .accept_agent_result(scan_id, &claiming, &artifacts, Some(&alongside))
            .await
            .map_err(|_| refusals::result_no_longer_yours())?;

        if !accepted {
            return Err(refusals::result_no_longer_yours());
        }

        Ok(())
    }

    pub async fn report_failure(
        &self,
        agent: &AuthenticatedAgent,
        scan_id: i64,
        body: &[u8],
        signature: Option<&str>,
        origin: &RequestActor,
    ) -> Result<FailureAnswer, RouteRefusal> {
        let pinned = agent.signing_public_key.as_deref().map(str::trim).filter(|p| !p.is_empty());
        if let Some(pinned) = pinned {
            let sig = signature.unwrap_or("").trim();
            if !verify_failure(pinned, scan_id, body, sig) {
                let desc = if sig.is_empty() {
                    format!(
                        "Failure report submitted with no attestation by agent \"{}\", whose signing key is pinned. The scan was left as it was.",
                        agent.name
                    )
                } else {
                    format!(
                        "Failure report submitted with an attestation that does not verify by agent \"{}\", whose signing key is pinned. The scan was left as it was.",
                        agent.name
                    )
                };
                self.record_audit(origin, AuditOperation::AgentResultRefused, &scan_id.to_string(), &desc).await;
                return Err(refusals::failure_not_attested(&agent.name));
            }
        }

        let report = FailureReport::read(body).map_err(|_| refusals::failure_unreadable())?;

        self.heard_from(agent).await;

        let reason = failure_reason::scrub(report.reason.as_deref().unwrap_or(""), []);
        let reason_clean = if reason.is_empty() { "the agent gave no reason." } else { &reason };

        let claiming = to_claiming_agent(agent);
        let failure = self
            .dispatcher
            .report_agent_failure(scan_id, &claiming, report.attempt, report.kind, reason_clean)
            .await
            .map_err(|_| refusals::failure_no_longer_yours())?;

        let Some(failure) = failure else {
            return Err(refusals::failure_no_longer_yours());
        };

        let attestation_note = if pinned.is_none() { " (not attested)" } else { ", attestation verified" };
        let outcome_note = if failure.retried {
            let not_before_str = failure
                .not_before
                .map(|nb| {
                    iso_instant(vectispire_domain::instant::Instant { epoch_second: nb.unix_timestamp(), nano: 0 })
                })
                .unwrap_or_default();
            format!("; back in the queue, not before {not_before_str}.")
        } else {
            "; the scan failed.".to_owned()
        };

        self.record_audit(
            origin,
            AuditOperation::AgentScanFailed,
            &scan_id.to_string(),
            &format!(
                "Agent \"{}\" reported it could not run attempt {} of {} of the scan, a {} failure{}{}",
                agent.name,
                failure.attempt,
                failure.max_attempts,
                report.kind.wire_name(),
                attestation_note,
                outcome_note
            ),
        )
        .await;

        Ok(FailureAnswer {
            retried: failure.retried,
            attempt: failure.attempt,
            max_attempts: failure.max_attempts,
            permanent: failure.permanent,
            retry_at: failure.not_before.map(|nb| vectispire_domain::instant::Instant {
                epoch_second: nb.unix_timestamp(),
                nano: nb.nanosecond(),
            }),
        })
    }

    pub async fn rule_set(&self, hash: &str) -> Result<Option<Vec<StoredFile>>, PortError> {
        let files = self.rule_sets.files_of(hash).await?;
        if files.is_empty() {
            return Ok(None);
        }
        Ok(Some(files))
    }

    pub async fn plugin(&self, id: &str, digest: &str) -> Result<Option<serde_json::Value>, PortError> {
        self.plugins.manifest(id, digest).await
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

struct AuditAlongside<'a> {
    outbox: &'a Outbox,
    scan_id: i64,
    description: String,
    agent_name: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

impl Alongside for AuditAlongside<'_> {
    fn write<'a>(&'a self, tx: &'a mut vectispire_cp_db::Tx) -> BoxFuture<'a, Result<(), PortError>> {
        Box::pin(async move {
            let payload = serde_json::json!({
                "scanId": self.scan_id,
                "description": self.description,
                "agentName": self.agent_name,
                "ipAddress": self.ip_address,
                "userAgent": self.user_agent,
            });
            self.outbox
                .enqueue(tx, &payload, crate::internal::audit::TYPE, None)
                .await
                .map_err(|e| Box::new(e) as PortError)?;
            Ok(())
        })
    }
}

fn to_claiming_agent(agent: &AuthenticatedAgent) -> ClaimingAgent {
    ClaimingAgent {
        id: agent.id,
        name: Some(agent.name.clone()),
        credentials_mode: Some(agent.credentials_mode.clone()),
        sealing_public_key: agent.sealing_public_key.clone(),
        signing_public_key: agent.signing_public_key.clone(),
        labels: agent.labels.clone(),
        max_concurrent: agent.max_concurrent.map(i64::from),
    }
}
