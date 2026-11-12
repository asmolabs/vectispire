//! Long polling for the agent protocol.

use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tokio::time::sleep;

use vectispire_cp_scanning::dispatcher::{AgentTask, ClaimError};
use vectispire_cp_scanning::{ClaimingAgent, ScanDispatcher};

use crate::error::AgentError;
use crate::internal::protocol_service::{AgentProtocolService, AuthenticatedAgent};

const MAX_WAIT: Duration = Duration::seconds(30);

/// A claimed task on its way to the agent — Java's delivery receipt, `DeferredResult.setResult`'s return value.
///
/// **Returned to the queue unless it was handed over.** Between the claim and the answer the agent can hang up: the
/// request's future is then dropped, or its answer is never written. Java answers that by `returnUndelivered`, because
/// a scan claimed by an agent that never received it "sat there until the lease lapsed". The Rust poller had no
/// receipt at all. This one is carried by the answer's body ([`crate::web`]), marked [`Receipt::handed_over`] when the
/// body's bytes are taken for writing, and on drop otherwise gives the scan back.
pub struct Receipt {
    dispatcher: Arc<ScanDispatcher>,
    scan_id: i64,
    agent: ClaimingAgent,
    handed_over: bool,
}

impl Receipt {
    fn new(dispatcher: Arc<ScanDispatcher>, scan_id: i64, agent: ClaimingAgent) -> Receipt {
        Receipt { dispatcher, scan_id, agent, handed_over: false }
    }

    /// The answer's bytes were taken by the server: the agent is reading them, or the connection failed afterwards,
    /// which Java cannot tell from a delivery either.
    pub fn handed_over(mut self) {
        self.handed_over = true;
    }
}

impl std::fmt::Debug for Receipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receipt").field("scan_id", &self.scan_id).field("handed_over", &self.handed_over).finish()
    }
}

impl Drop for Receipt {
    fn drop(&mut self) {
        if self.handed_over {
            return;
        }
        let dispatcher = self.dispatcher.clone();
        let (scan_id, agent) = (self.scan_id, self.agent.clone());
        // Dropped on a runtime thread: the request's future or its body. Outside a runtime there is nobody to give the
        // scan back, and the lease lapses as before.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(failure) = dispatcher.return_undelivered(scan_id, &agent).await {
                    tracing::warn!(scan_id, error = %failure, "An undelivered scan could not be given back; its lease will lapse.");
                }
            });
        }
    }
}

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

    pub async fn claim(
        &self,
        agent: &AuthenticatedAgent,
        wait_seconds: i32,
    ) -> Result<Option<(AgentTask, Receipt)>, AgentError> {
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

        if let Some(task) = immediate {
            return Ok(Some(self.receipted(task, &claiming)));
        }
        if wait.is_zero() {
            return Ok(None);
        }

        let deadline = OffsetDateTime::now_utc().checked_add(wait).unwrap_or_else(OffsetDateTime::now_utc);

        loop {
            sleep(std::time::Duration::from_secs(1)).await;

            match self.dispatcher.claim_for_agent(&claiming).await {
                Ok(Some(task)) => return Ok(Some(self.receipted(task, &claiming))),
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

impl AgentJobPoller {
    fn receipted(&self, task: AgentTask, agent: &ClaimingAgent) -> (AgentTask, Receipt) {
        let receipt = Receipt::new(self.dispatcher.clone(), task.scan_id, agent.clone());
        (task, receipt)
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
