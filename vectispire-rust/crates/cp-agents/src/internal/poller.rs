//! Long polling for the agent protocol.

use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tokio::time::sleep;

use vectispire_cp_scanning::dispatcher::{AgentTask, ClaimError};
use vectispire_cp_scanning::{ClaimingAgent, ScanDispatcher};

use crate::error::AgentError;
use crate::internal::protocol_service::{AgentProtocolService, AuthenticatedAgent};

const MAX_WAIT: Duration = Duration::seconds(30);

#[derive(Clone)]
pub struct AgentJobPoller {
    dispatcher: Arc<ScanDispatcher>,
    protocol: Arc<AgentProtocolService>,
}

impl std::fmt::Debug for AgentJobPoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentJobPoller").finish_non_exhaustive()
    }
}

impl AgentJobPoller {
    pub fn new(dispatcher: Arc<ScanDispatcher>, protocol: Arc<AgentProtocolService>) -> Self {
        Self { dispatcher, protocol }
    }

    pub async fn claim(&self, agent: &AuthenticatedAgent, wait_seconds: i32) -> Result<Option<AgentTask>, AgentError> {
        let wait = if wait_seconds < 0 { Duration::ZERO } else { Duration::seconds(wait_seconds as i64).min(MAX_WAIT) };

        self.protocol.heard_from(agent).await;

        let claiming = to_claiming_agent(agent);
        let immediate = match self.dispatcher.claim_for_agent(&claiming).await {
            Ok(task) => task,
            Err(ClaimError::Withheld(withheld)) => {
                return Err(AgentError::PreconditionFailed(withheld.message().to_owned()));
            }
            Err(ClaimError::Failed(err)) => {
                return Err(AgentError::Unexpected(err));
            }
        };

        if immediate.is_some() || wait.is_zero() {
            return Ok(immediate);
        }

        let deadline = OffsetDateTime::now_utc().checked_add(wait).unwrap_or_else(OffsetDateTime::now_utc);

        loop {
            sleep(std::time::Duration::from_secs(1)).await;

            match self.dispatcher.claim_for_agent(&claiming).await {
                Ok(Some(task)) => return Ok(Some(task)),
                Ok(None) => {
                    if OffsetDateTime::now_utc() >= deadline {
                        return Ok(None);
                    }
                }
                Err(ClaimError::Withheld(withheld)) => {
                    return Err(AgentError::PreconditionFailed(withheld.message().to_owned()));
                }
                Err(ClaimError::Failed(err)) => {
                    return Err(AgentError::Unexpected(err));
                }
            }
        }
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
