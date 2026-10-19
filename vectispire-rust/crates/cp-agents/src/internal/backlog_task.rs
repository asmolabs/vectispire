//! `CredentialedBacklogTask`: warns when scans needing a credential wait with no executor able to take them.

use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use tracing::{info, warn};
use vectispire_cp_maintenance::{MaintenanceTask, Sequence, TaskRun};

pub const QUIET: Duration = Duration::minutes(15);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unserved {
    pub scans: i64,
    pub labels: Vec<String>,
    pub kept_agents: Vec<String>,
}

pub trait CredentialedBacklogProvider: Send + Sync + std::fmt::Debug {
    fn unserved(
        &self,
    ) -> vectispire_cp_http::credentials::BoxFuture<'_, Result<Unserved, Box<dyn std::error::Error + Send + Sync>>>;
}

#[derive(Debug)]
pub struct CredentialedBacklogTask {
    provider: Arc<dyn CredentialedBacklogProvider>,
    state: Mutex<TaskState>,
}

#[derive(Debug, Default)]
struct TaskState {
    last_warned: Option<OffsetDateTime>,
    last_warned_count: i64,
}

#[derive(Debug, PartialEq, Eq)]
enum Say {
    Nothing,
    Warning,
    Cleared,
}

impl CredentialedBacklogTask {
    pub fn new(provider: Arc<dyn CredentialedBacklogProvider>) -> Self {
        Self { provider, state: Mutex::new(TaskState::default()) }
    }

    fn decide(&self, state: &mut TaskState, unserved: &Unserved, now: OffsetDateTime) -> Say {
        if unserved.scans == 0 {
            if state.last_warned.is_none() {
                return Say::Nothing;
            }
            state.last_warned = None;
            state.last_warned_count = 0;
            return Say::Cleared;
        }

        let due = match state.last_warned {
            None => true,
            Some(last) => {
                last.checked_add(QUIET).is_none_or(|due| now >= due) || unserved.scans > state.last_warned_count
            }
        };

        if !due {
            return Say::Nothing;
        }

        state.last_warned = Some(now);
        state.last_warned_count = unserved.scans;
        Say::Warning
    }
}

impl MaintenanceTask for CredentialedBacklogTask {
    fn sequence(&self) -> Sequence {
        Sequence::CredentialedBacklog
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            let unserved = self.provider.unserved().await?;
            let now = OffsetDateTime::now_utc();
            let mut state = self.state.lock().await;
            match self.decide(&mut state, &unserved, now) {
                Say::Warning => {
                    let labels_str = unserved
                        .labels
                        .iter()
                        .map(|l| if l.is_empty() { "none" } else { l.as_str() })
                        .collect::<Vec<_>>()
                        .join(", ");
                    let agents_str = if unserved.kept_agents.is_empty() {
                        "No enabled agent serves them.".to_owned()
                    } else {
                        format!(
                            "Enabled agents that would take them but hold no verified sealing key: {}.",
                            unserved.kept_agents.join(", ")
                        )
                    };
                    warn!(
                        "{} scan(s) of repositories carrying a credential are waiting, and no executor able to be handed it serves them (required label: {}). {} Pin a signing key and update a delegated agent, or run a local agent or the built-in worker; the gauge vectispire.scans.credential.unserved counts them.",
                        unserved.scans, labels_str, agents_str
                    );
                }
                Say::Cleared => {
                    info!(
                        "The scans needing a credential are served again: an executor able to be handed it takes them."
                    );
                }
                Say::Nothing => {}
            }
            Ok(())
        })
    }
}
