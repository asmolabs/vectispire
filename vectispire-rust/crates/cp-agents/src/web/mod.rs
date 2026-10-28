//! Routes for agent protocol and administration.

mod admin;
mod protocol;

use std::sync::Arc;
use vectispire_cp_http::routes::RouteEntry;

use crate::Agents;

pub fn routes(agents: Arc<Agents>) -> Vec<RouteEntry> {
    let mut entries = Vec::new();
    entries.extend(admin::routes(agents.admin.clone()));
    entries.extend(protocol::routes(agents.protocol.clone(), agents.poller.clone()));
    entries
}
