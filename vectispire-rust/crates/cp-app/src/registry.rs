//! Every route the control plane registers: targets (29), scanning (3), agents (17), rules (9), inventory (18).

use std::sync::Arc;

use vectispire_cp_agents::Agents;
use vectispire_cp_http::routes::{NoVisibility, RouteEntry, Routes};
use vectispire_cp_inventory::Inventory;
use vectispire_cp_rules::RulesModule;
use vectispire_cp_scanning::Scanning;
use vectispire_cp_targets::Targets;

/// All route entries from the composed modules.
pub fn entries(
    targets: Arc<Targets>,
    scanning: Arc<Scanning>,
    agents: Arc<Agents>,
    rules: Arc<RulesModule>,
    inventory: Arc<Inventory>,
) -> Vec<RouteEntry> {
    let mut list = Vec::new();
    list.extend(vectispire_cp_targets::routes(targets.clone()));
    list.extend(vectispire_cp_scanning::routes(scanning));
    list.extend(vectispire_cp_agents::routes(agents));
    list.extend(rules.routes());
    list.extend(vectispire_cp_inventory::routes(inventory, targets));
    list
}

/// The registry, with every module's routes added.
#[must_use]
pub fn routes(
    targets: Arc<Targets>,
    scanning: Arc<Scanning>,
    agents: Arc<Agents>,
    rules: Arc<RulesModule>,
    inventory: Arc<Inventory>,
) -> Routes<()> {
    let mut routes = Routes::new(NoVisibility);
    for entry in entries(targets, scanning, agents, rules, inventory) {
        routes = routes.route(entry);
    }
    routes
}
