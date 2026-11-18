//! The checklists module (wave 1) as the binary composes it: its measurements over the owners' catalogues — the
//! plugins' imports and the forges' readings as the stand-ins their modules replace (waves 2 and 3) — documents
//! signed with the platform's key, the accounts and their visibility from `access`, the weekly reminder with no mail
//! relay until `notifications` is ported.

use std::sync::{Arc, OnceLock};

use vectispire_cp_checklists as checklists;
use vectispire_cp_checklists::project_checklists::ProjectChecklists;
use vectispire_cp_db::Db;
use vectispire_cp_http::routes::RouteEntry;
use vectispire_cp_maintenance::MaintenanceTask;

/// What composing the module gives the binary.
#[allow(missing_debug_implementations)] // services and routes
pub struct Composed {
    pub routes: Vec<RouteEntry>,
    pub reminders: Arc<dyn MaintenanceTask>,
    pub checklists: Arc<ProjectChecklists>,
}

/// What the module is composed over.
#[allow(missing_debug_implementations)] // services and pools
pub struct ChecklistParts {
    pub db: Db,
    pub targets: Arc<vectispire_cp_targets::Targets>,
    pub scans: vectispire_cp_scanning::ScanCatalog,
    pub issues: vectispire_cp_issues::IssueCatalog,
    pub audit: Arc<vectispire_cp_audit::AuditLog>,
    pub trail: Arc<vectispire_cp_audit::AuditLogQuery>,
    pub signing: Arc<vectispire_cp_crypto::SigningKeys>,
    pub visibility: vectispire_cp_access::VisibilityService,
    pub clock: Arc<dyn vectispire_cp_targets::Clock>,
    pub product_version: Option<String>,
    /// `vectispire.http.max-body.checklist-template-import` and `…checklist-evidence`.
    pub max_workbook_bytes: i64,
    pub max_file_bytes: i64,
}

/// The outbox handler of `checklist_answer`, registered before the services exist: the outbox is built with every
/// handler, and the services audit through the log the outbox's SIEM delivery is part of.
pub fn answer_delivery() -> (Arc<checklists::ChecklistAnswerDelivery>, Arc<OnceLock<Arc<ProjectChecklists>>>) {
    let slot = Arc::new(OnceLock::new());
    (Arc::new(checklists::ChecklistAnswerDelivery { checklists: slot.clone() }), slot)
}

/// The module, composed.
pub fn compose(parts: ChecklistParts) -> Composed {
    let ChecklistParts {
        db,
        targets,
        scans,
        issues,
        audit,
        trail,
        signing,
        visibility,
        clock,
        product_version,
        max_workbook_bytes,
        max_file_bytes,
    } = parts;
    let settings = Arc::new(vectispire_cp_settings::Settings::new(db.clone()));
    let measurer = checklists::measurer::Measurer::new(
        Arc::new(checklists::OwnerCatalogs {
            scans,
            issues,
            components: vectispire_cp_inventory::component_catalog::ComponentCatalog::new(db.clone()),
            targets: targets.clone(),
        }),
        Arc::new(checklists::measurer::NoImports),
        Arc::new(checklists::measurer::NoReviews),
    );
    let projects: Arc<dyn checklists::ports::ProjectDirectory> = Arc::new(checklists::TargetProjects(targets));
    let independence = vectispire_cp_access::independence::ApproverIndependence::new(db.clone(), settings.clone());
    let documents = Arc::new(checklists::documents::Documents::new(
        db.clone(),
        projects.clone(),
        measurer.clone(),
        Arc::new(checklists::PlatformSigner(signing)),
        product_version,
        audit.clone(),
        clock.clone(),
    ));
    let templates = Arc::new(checklists::templates::ChecklistTemplates::new(
        db.clone(),
        settings.clone(),
        audit.clone(),
        independence.clone(),
        clock.clone(),
        max_workbook_bytes,
    ));
    let project_checklists =
        Arc::new(ProjectChecklists::new(checklists::project_checklists::ProjectChecklistsConfig {
            db: db.clone(),
            projects: projects.clone(),
            measurer,
            documents: documents.clone(),
            trials: Arc::new(checklists::trials::VersionTrials::new()),
            settings: settings.clone(),
            audit: audit.clone(),
            independence,
            clock: clock.clone(),
            max_file_bytes,
        }));
    let accounts: Arc<dyn checklists::ports::AccountDirectory> = Arc::new(checklists::AccessAccounts {
        directory: vectispire_cp_access::account_names::AccountDirectory::new(
            vectispire_cp_access::SqlAccountStore::new(db.clone(), vectispire_cp_access::CredentialTables),
        ),
        visibility,
    });
    let contacts = Arc::new(checklists::contact_service::ChecklistContacts::new(
        db.clone(),
        projects.clone(),
        accounts.clone(),
        audit.clone(),
        clock.clone(),
    ));
    let reminders = Arc::new(checklists::contact_service::ChecklistReminders::new(
        db,
        projects,
        accounts,
        settings,
        Arc::new(checklists::ports::NoMail),
        trail,
        audit,
        clock,
    ));
    let routes = checklists::routes(checklists::ChecklistServices {
        templates,
        checklists: project_checklists.clone(),
        documents,
        contacts,
    });
    Composed {
        routes,
        reminders: Arc::new(checklists::ChecklistReminderTask { reminders }),
        checklists: project_checklists,
    }
}
