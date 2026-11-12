//! Every route the control plane registers: targets (29), scanning (3), agents (17), rules (9), inventory (18), issues
//! (10), gate (7), siem (3), platform (6 so far: the audit trail's and the signing key's).

use std::sync::Arc;

use vectispire_cp_agents::Agents;
use vectispire_cp_gate::GateModule;
use vectispire_cp_http::routes::{NoVisibility, RouteEntry, Routes};
use vectispire_cp_inventory::Inventory;
use vectispire_cp_rules::RulesModule;
use vectispire_cp_scanning::Scanning;
use vectispire_cp_siem::SiemExporterService;
use vectispire_cp_targets::Targets;

/// The platform routes' services: the audit trail's reader and the document signing key.
#[derive(Clone, Debug)]
pub struct Platform {
    pub trail: Arc<vectispire_cp_audit::AuditLogQuery>,
    pub signing: Arc<vectispire_cp_crypto::SigningKeys>,
}

/// All route entries from the composed modules.
#[allow(clippy::too_many_arguments)]
pub fn entries(
    targets: Arc<Targets>,
    scanning: Arc<Scanning>,
    agents: Arc<Agents>,
    rules: Arc<RulesModule>,
    inventory: Arc<Inventory>,
    issues: Arc<vectispire_cp_issues::Issues>,
    gate: Arc<GateModule>,
    siem: Arc<SiemExporterService>,
    platform: Platform,
) -> Vec<RouteEntry> {
    let mut list = Vec::new();
    list.extend(vectispire_cp_targets::routes(targets.clone()));
    list.extend(vectispire_cp_scanning::routes(scanning));
    list.extend(vectispire_cp_agents::routes(agents));
    list.extend(rules.routes());
    list.extend(vectispire_cp_inventory::routes(inventory, targets));
    list.extend(vectispire_cp_issues::routes(issues));
    list.extend(gate.routes());
    list.extend(vectispire_cp_siem::routes(siem));
    list.extend(vectispire_cp_platform::routes(platform.trail, platform.signing));
    list
}

/// The registry, with every module's routes added.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn routes(
    targets: Arc<Targets>,
    scanning: Arc<Scanning>,
    agents: Arc<Agents>,
    rules: Arc<RulesModule>,
    inventory: Arc<Inventory>,
    issues: Arc<vectispire_cp_issues::Issues>,
    gate: Arc<GateModule>,
    siem: Arc<SiemExporterService>,
    platform: Platform,
) -> Routes<()> {
    let mut routes = Routes::new(NoVisibility);
    for entry in entries(targets, scanning, agents, rules, inventory, issues, gate, siem, platform) {
        routes = routes.route(entry);
    }
    routes
}
