//! The checklist routes against the contract they must not change: documented under the same method and path, with
//! Java's operation ids and query parameters, out of `cp-contract`'s `not-yet-ported/` since the commit that ported
//! them, each behind Java's marker — then the router probed, so a route declared and not registered is caught too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_checklists::contact_service::ChecklistContacts;
use vectispire_cp_checklists::documents::Documents;
use vectispire_cp_checklists::measurer::{Answer, Measurer, NoImports, NoReviews};
use vectispire_cp_checklists::ports::{AccountDirectory, DocumentSigner, ProjectDirectory, ProjectMembers};
use vectispire_cp_checklists::project_checklists::{ProjectChecklists, ProjectChecklistsConfig};
use vectispire_cp_checklists::templates::ChecklistTemplates;
use vectispire_cp_checklists::trials::VersionTrials;
use vectispire_cp_checklists::{ChecklistServices, routes};
use vectispire_cp_contract::{
    Allowlist, Document, Published, RouteDecl, assert_none, check_module, check_published, probe,
};
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_http::access::Access;
use vectispire_cp_http::chain::{Chain, ChainConfig};
use vectispire_cp_http::credentials::{RecordingAudit, StaticCredentials};
use vectispire_cp_http::principal::ApiKeyScope;
use vectispire_cp_http::routes::{NoVisibility, Routes};

/// Method, path, operation id, and the query parameters the handler reads.
const DECLARED: &[(&str, &str, &str, &[&str])] = &[
    ("GET", "/api/v1/checklist-templates", "listTemplates", &["limit", "offset"]),
    ("GET", "/api/v1/checklist-templates/{slug}", "readTemplate", &[]),
    ("POST", "/api/v1/checklist-templates/{slug}/versions", "importWorkbook", &["name", "label"]),
    ("GET", "/api/v1/checklist-templates/{slug}/versions/{ordinal}", "readVersion", &[]),
    ("POST", "/api/v1/checklist-templates/{slug}/versions/{ordinal}/derive", "deriveVersion", &[]),
    ("PUT", "/api/v1/checklist-templates/{slug}/versions/{ordinal}/evidence", "setEvidence", &["revision"]),
    ("PUT", "/api/v1/checklist-templates/{slug}/versions/{ordinal}/layout", "confirmLayout", &["revision"]),
    ("PUT", "/api/v1/checklist-templates/{slug}/versions/{ordinal}/pairs", "pairItems", &["revision"]),
    ("GET", "/api/v1/checklist-templates/{slug}/versions/{ordinal}/preview", "previewVersion", &["sheet"]),
    ("POST", "/api/v1/checklist-templates/{slug}/versions/{ordinal}/publish", "publishVersion", &[]),
    ("POST", "/api/v1/checklist-templates/{slug}/versions/{ordinal}/retire", "retireVersion", &[]),
    ("PUT", "/api/v1/checklist-templates/{slug}/versions/{ordinal}/rules", "bindRules", &["revision"]),
    ("GET", "/api/v1/projects/{projectId}/checklists", "list_10", &["limit", "offset"]),
    ("POST", "/api/v1/projects/{projectId}/checklists", "open", &[]),
    ("GET", "/api/v1/projects/{projectId}/checklists/contacts", "checklistContacts", &[]),
    (
        "GET",
        "/api/v1/projects/{projectId}/checklists/contacts/candidates",
        "checklistContactCandidates",
        &["limit", "offset"],
    ),
    ("DELETE", "/api/v1/projects/{projectId}/checklists/contacts/{profile}", "unlinkChecklistContact", &[]),
    ("PUT", "/api/v1/projects/{projectId}/checklists/contacts/{profile}", "linkChecklistContact", &[]),
    ("GET", "/api/v1/projects/{projectId}/checklists/context", "context", &[]),
    ("GET", "/api/v1/projects/{projectId}/checklists/offered", "offered", &[]),
    ("GET", "/api/v1/projects/{projectId}/checklists/{revision}", "read", &[]),
    ("POST", "/api/v1/projects/{projectId}/checklists/{revision}/answers/as-measured", "answerAsMeasured", &[]),
    ("GET", "/api/v1/projects/{projectId}/checklists/{revision}/document", "checklistDocument", &[]),
    ("GET", "/api/v1/projects/{projectId}/checklists/{revision}/evidence/{evidenceId}/file", "download", &[]),
    ("POST", "/api/v1/projects/{projectId}/checklists/{revision}/evidence/{evidenceId}/withdrawal", "withdraw_1", &[]),
    ("POST", "/api/v1/projects/{projectId}/checklists/{revision}/items/{itemId}/answers", "answer", &[]),
    ("POST", "/api/v1/projects/{projectId}/checklists/{revision}/items/{itemId}/confirmation", "confirm", &[]),
    (
        "POST",
        "/api/v1/projects/{projectId}/checklists/{revision}/items/{itemId}/evidence/files",
        "attachFile",
        &["name", "performedOn", "edition"],
    ),
    ("POST", "/api/v1/projects/{projectId}/checklists/{revision}/items/{itemId}/evidence/links", "attachLink", &[]),
    ("GET", "/api/v1/projects/{projectId}/checklists/{revision}/items/{itemId}/history", "history_1", &[]),
    ("GET", "/api/v1/projects/{projectId}/checklists/{revision}/measurements", "measurements", &[]),
    ("POST", "/api/v1/projects/{projectId}/checklists/{revision}/reopen", "reopen", &[]),
    ("POST", "/api/v1/projects/{projectId}/checklists/{revision}/return", "returnToAuthors", &[]),
    ("POST", "/api/v1/projects/{projectId}/checklists/{revision}/sign-off", "signOff", &[]),
    ("POST", "/api/v1/projects/{projectId}/checklists/{revision}/submission", "submit", &[]),
];

/// The ports the probe never reaches: it asks the routes' shape, not a project.
struct Nobody;

impl ProjectDirectory for Nobody {
    fn members<'a>(&'a self, _: i64) -> Answer<'a, Option<ProjectMembers>> {
        Box::pin(async { Ok(None) })
    }
    fn project_of<'a>(&'a self, _: i64) -> Answer<'a, Option<i64>> {
        Box::pin(async { Ok(None) })
    }
    fn repository_names<'a>(&'a self, _: &'a [i64]) -> Answer<'a, std::collections::BTreeMap<i64, String>> {
        Box::pin(async { Ok(std::collections::BTreeMap::new()) })
    }
}

impl AccountDirectory for Nobody {
    fn active<'a>(&'a self) -> Answer<'a, Vec<vectispire_cp_access::accounts::UserView>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn by_id<'a>(&'a self, _: i64) -> Answer<'a, Option<vectispire_cp_access::accounts::UserView>> {
        Box::pin(async { Ok(None) })
    }
    fn allowance_of<'a>(
        &'a self,
        _: &'a vectispire_cp_access::accounts::UserView,
    ) -> Answer<'a, vectispire_cp_access::visibility::Allowance> {
        Box::pin(async { Ok(vectispire_cp_access::visibility::Allowance::nothing()) })
    }
}

impl DocumentSigner for Nobody {
    fn key_id<'a>(&'a self) -> Answer<'a, String> {
        Box::pin(async { Err("no key".to_owned()) })
    }
    fn sign<'a>(&'a self, _: &'a [u8]) -> Answer<'a, String> {
        Box::pin(async { Err("no key".to_owned()) })
    }
}

fn unreachable_db() -> vectispire_cp_db::Db {
    let settings = DbSettings {
        url: DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: PoolSettings::default(),
        ca_pem: None,
    };
    vectispire_cp_db::Db::connect_lazy(&settings).unwrap()
}

fn services() -> ChecklistServices {
    let db = unreachable_db();
    let clock: Arc<dyn vectispire_cp_targets::Clock> = Arc::new(vectispire_cp_targets::SystemClock);
    let settings = Arc::new(vectispire_cp_settings::Settings::new(db.clone()));
    let audit = Arc::new(vectispire_cp_audit::AuditLog::new(
        db.clone(),
        Arc::new(vectispire_cp_audit::NoMirror),
        Arc::new(vectispire_cp_audit::SystemClock),
        Vec::new(),
    ));
    let independence = vectispire_cp_access::independence::ApproverIndependence::new(db.clone(), settings.clone());
    let projects: Arc<dyn ProjectDirectory> = Arc::new(Nobody);
    let measurer = Measurer::new(Arc::new(NoScans), Arc::new(NoImports), Arc::new(NoReviews));
    let documents = Arc::new(Documents::new(
        db.clone(),
        projects.clone(),
        measurer.clone(),
        Arc::new(Nobody),
        None,
        audit.clone(),
        clock.clone(),
    ));
    ChecklistServices {
        templates: Arc::new(ChecklistTemplates::new(
            db.clone(),
            settings.clone(),
            audit.clone(),
            independence.clone(),
            clock.clone(),
            1,
        )),
        checklists: Arc::new(ProjectChecklists::new(ProjectChecklistsConfig {
            db: db.clone(),
            projects: projects.clone(),
            measurer,
            documents: documents.clone(),
            trials: Arc::new(VersionTrials::new()),
            settings,
            audit: audit.clone(),
            independence,
            clock: clock.clone(),
            max_file_bytes: 1,
        })),
        documents,
        contacts: Arc::new(ChecklistContacts::new(db, projects, Arc::new(Nobody), audit, clock)),
    }
}

/// No scan, no backlog, no inventory, no schedule: the probe never measures.
struct NoScans;

impl vectispire_cp_checklists::measurer::ScanEvidence for NoScans {
    fn newest_examining<'a>(
        &'a self,
        _: &'a [i64],
        _: vectispire_domain::finding_type::FindingType,
    ) -> Answer<'a, std::collections::BTreeMap<i64, vectispire_cp_checklists::measurer::ExaminingScan>> {
        Box::pin(async { Err("not asked".to_owned()) })
    }
    fn completed_within<'a>(
        &'a self,
        _: &'a [i64],
        _: vectispire_domain::instant::Instant,
    ) -> Answer<'a, std::collections::BTreeMap<i64, vectispire_cp_checklists::measurer::ScansWithin>> {
        Box::pin(async { Err("not asked".to_owned()) })
    }
    fn plugin_runs_within<'a>(
        &'a self,
        _: &'a [i64],
        _: &'a str,
        _: vectispire_domain::instant::Instant,
    ) -> Answer<'a, std::collections::BTreeMap<i64, Vec<vectispire_cp_checklists::measurer::PluginRunRow>>> {
        Box::pin(async { Err("not asked".to_owned()) })
    }
    fn naming_plugin_before<'a>(
        &'a self,
        _: &'a [i64],
        _: &'a str,
        _: vectispire_domain::instant::Instant,
    ) -> Answer<'a, BTreeSet<i64>> {
        Box::pin(async { Err("not asked".to_owned()) })
    }
    fn languages_of<'a>(
        &'a self,
        _: &'a [i64],
    ) -> Answer<'a, std::collections::BTreeMap<i64, vectispire_domain::checklists::facts::ScanLanguages>> {
        Box::pin(async { Err("not asked".to_owned()) })
    }
    fn count_unsettled_of_type<'a>(
        &'a self,
        _: vectispire_domain::finding_type::FindingType,
        _: &'a [i64],
    ) -> Answer<'a, Vec<vectispire_cp_checklists::measurer::ScopeCount>> {
        Box::pin(async { Err("not asked".to_owned()) })
    }
    fn count_unsettled_of_tool<'a>(
        &'a self,
        _: &'a str,
        _: &'a [i64],
    ) -> Answer<'a, Vec<vectispire_cp_checklists::measurer::ScopeCount>> {
        Box::pin(async { Err("not asked".to_owned()) })
    }
    fn components_of<'a>(
        &'a self,
        _: &'a [i64],
    ) -> Answer<'a, std::collections::BTreeMap<i64, Vec<vectispire_domain::checklists::facts::Component>>> {
        Box::pin(async { Err("not asked".to_owned()) })
    }
    fn scheduled<'a>(
        &'a self,
        _: &'a [i64],
        _: i32,
        _: vectispire_domain::instant::Instant,
    ) -> Answer<'a, std::collections::BTreeMap<i64, bool>> {
        Box::pin(async { Err("not asked".to_owned()) })
    }
}

#[tokio::test]
async fn the_routes_are_the_documented_ones() {
    let entries = routes(services());
    assert_eq!(entries.len(), DECLARED.len());
    // Java's markers: a template read is governance's, a template written a security lead's; a project's checklist
    // read by any account, written by the roles that cause effects; the candidates a writer's; the document the one
    // route an integration key with the export scope reaches.
    for entry in &entries {
        let decl = entry.decl();
        let expected = match (decl.method.as_str(), decl.path.as_str()) {
            ("GET", path) if path.starts_with("/api/v1/checklist-templates") => Access::GovernanceRead,
            (_, path) if path.starts_with("/api/v1/checklist-templates") => Access::SecurityLead,
            ("GET", "/api/v1/projects/{projectId}/checklists/contacts/candidates") => Access::WriteAccount,
            ("GET", _) => Access::Account,
            _ => Access::WriteAccount,
        };
        assert_eq!(decl.access, expected, "{} {}", decl.method, decl.path);
        let document = decl.path.ends_with("/document");
        assert_eq!(decl.accepts_api_key, document.then_some(ApiKeyScope::Export), "{}", decl.path);
    }

    let declared: Vec<RouteDecl> = DECLARED
        .iter()
        .map(|(method, path, id, query)| {
            let route = query.iter().fold(RouteDecl::new(method, path, id), |route, name| route.query(name, false));
            // The proof's file: its `Content-Type` stored, never trusted.
            if path.ends_with("/evidence/files") { route.header("content-type", false) } else { route }
        })
        .collect();
    let document = Document::embedded();
    let ours: BTreeSet<(String, String)> =
        declared.iter().map(|route| (route.method.clone(), route.path.clone())).collect();
    let not_ours = Allowlist::all_but(&document, &ours);
    assert_none(&check_module(&document, &declared, &Allowlist::committed()));
    assert_none(&check_published(&document, &Published::embedded(), Some(&declared)));

    let mut router = Routes::new(NoVisibility);
    for entry in entries {
        router = router.route(entry);
    }
    let chain = Arc::new(Chain::new(
        ChainConfig::default(),
        Arc::new(StaticCredentials::default()),
        Arc::new(RecordingAudit::default()),
    ));
    let router = router.build(&chain, None).unwrap();
    assert_none(&probe(&router, &document, &not_ours).await);
}
