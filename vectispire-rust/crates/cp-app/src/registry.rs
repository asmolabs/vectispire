//! Every route the control plane registers: targets (29), scanning (3), agents (17), rules (9), inventory (18), issues
//! (10), gate (7), posture (18), siem (3), platform (10 so far: the audit trail's, the signing key's, the integrations' and the
//! settings catalog's and save).

use std::sync::Arc;

use vectispire_cp_agents::Agents;
use vectispire_cp_gate::GateModule;
use vectispire_cp_http::routes::{NoVisibility, RouteEntry, Routes};
use vectispire_cp_inventory::Inventory;
use vectispire_cp_posture::PostureModule;
use vectispire_cp_rules::RulesModule;
use vectispire_cp_scanning::Scanning;
use vectispire_cp_siem::SiemExporterService;
use vectispire_cp_targets::Targets;

/// The platform routes' services: the audit trail's reader, the document signing key, the integrations' switches and
/// the settings screen (`settings_screen::compose`).
#[derive(Clone, Debug)]
pub struct Platform {
    pub trail: Arc<vectispire_cp_audit::AuditLogQuery>,
    pub signing: Arc<vectispire_cp_crypto::SigningKeys>,
    pub integrations: Arc<vectispire_cp_platform::IntegrationAdministration>,
    pub settings: Arc<vectispire_cp_platform::SettingsAdministration>,
}

/// The integrations' registry as the governor switches it (decision 0040 §3): asked of every module whose
/// configuration may be using an integration. **One list, here**: an owner missing from it is an integration switched
/// off under a configuration that uses it. The SIEM export answers for its transports; the notification channels'
/// answer (`NotificationDestinations`) joins it with the notifications module, not ported yet — until then nothing
/// refuses switching off a channel in use, and the routes of those channels are not served either.
pub fn integration_administration(
    db: &vectispire_cp_db::Db,
    audit: vectispire_cp_audit::AuditLog,
) -> Arc<vectispire_cp_platform::IntegrationAdministration> {
    Arc::new(vectispire_cp_platform::IntegrationAdministration::new(integrations(db), audit))
}

/// The integrations' registry, with every owner that answers "in use" — the governor's switches and the settings save
/// read the same one.
pub fn integrations(db: &vectispire_cp_db::Db) -> vectispire_cp_settings::Integrations {
    let uses: Vec<Arc<dyn vectispire_cp_settings::InUse>> = vec![Arc::new(vectispire_cp_siem::SiemTransportInUse)];
    vectispire_cp_settings::Integrations::new(db.clone(), uses, Arc::new(time::OffsetDateTime::now_utc))
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
    posture: Arc<PostureModule>,
    siem: Arc<SiemExporterService>,
    platform: Platform,
    compliance: Arc<vectispire_cp_compliance::Services>,
) -> Vec<RouteEntry> {
    let mut list = Vec::new();
    list.extend(vectispire_cp_targets::routes(targets.clone()));
    list.extend(vectispire_cp_scanning::routes(scanning));
    list.extend(vectispire_cp_agents::routes(agents));
    list.extend(rules.routes());
    list.extend(vectispire_cp_inventory::routes(inventory, targets));
    list.extend(vectispire_cp_issues::routes(issues));
    list.extend(gate.routes());
    list.extend(posture.routes());
    list.extend(vectispire_cp_compliance::routes(compliance));
    list.extend(vectispire_cp_siem::routes(siem));
    list.extend(vectispire_cp_platform::routes(platform.trail, platform.signing));
    list.extend(vectispire_cp_platform::integration_routes(platform.integrations));
    list.extend(vectispire_cp_platform::settings_routes(platform.settings));
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
    posture: Arc<PostureModule>,
    siem: Arc<SiemExporterService>,
    platform: Platform,
    compliance: Arc<vectispire_cp_compliance::Services>,
) -> Routes<()> {
    let mut routes = Routes::new(NoVisibility);
    for entry in entries(targets, scanning, agents, rules, inventory, issues, gate, posture, siem, platform, compliance)
    {
        routes = routes.route(entry);
    }
    routes
}
