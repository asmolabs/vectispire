//! Implementation of `cp_scanning::ports::AgentClaimLock`.

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::Tx;
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_scanning::ports::{AgentClaimLock, PortError};

use crate::persistence::agents;

#[derive(Debug, Default, Clone, Copy)]
pub struct AgentRowLock;

impl AgentClaimLock for AgentRowLock {
    fn lock_for_claim<'a>(
        &'a self,
        tx: &'a mut Tx,
        agent: Uuid,
        at: OffsetDateTime,
    ) -> BoxFuture<'a, Result<bool, PortError>> {
        Box::pin(async move { agents::lock_for_claim(tx, agent, at).await.map_err(|e| Box::new(e) as PortError) })
    }
}
