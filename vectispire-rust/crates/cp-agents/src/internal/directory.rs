//! Implementation of `cp_access::credentials::AgentDirectory`.

use uuid::Uuid;
use vectispire_cp_access::credentials::{AgentDirectory, AgentRef, StoreError};
use vectispire_cp_db::Db;
use vectispire_cp_http::credentials::BoxFuture;

use crate::persistence::agents;

#[derive(Debug, Clone)]
pub struct AgentDirectoryImpl {
    db: Db,
}

impl AgentDirectoryImpl {
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

impl AgentDirectory for AgentDirectoryImpl {
    fn by_api_key<'a>(&'a self, key_id: Uuid) -> BoxFuture<'a, Result<Option<AgentRef>, StoreError>> {
        Box::pin(async move { agents::by_api_key(&self.db, key_id).await.map_err(|e| StoreError::from_port(e.0)) })
    }
}
