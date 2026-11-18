//! `ForgeSelectionService` and `ForgeImportService` — choosing which of a discovery's repositories to import, seeing
//! what the import would do, and doing it (decision 0037 §4–5).
//!
//! **The selection is a set of forge ids**, held by the screen and sent with each gesture: what is imported is what
//! was ticked, never what a filter matches at import time. **Up to 1,000 repositories in one transaction**, created
//! through the targets' own gestures with the provenance link beside each; **planned again inside the transaction**,
//! and once more from what is committed when it lost a race. **Audited after the commit**: each creation's entry, then
//! one `FORGE_IMPORT_APPLIED`, signalled once and only when something was created.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use serde::Serialize;
use vectispire_cp_audit::{AuditLog, AuditOperation, RequestActor, Signal};
use vectispire_cp_targets::Targets;
use vectispire_domain::bounded_text::{self, Refused};
use vectispire_domain::forges::selection::{Candidate, Judged, Requested, SelectionFilter};
use vectispire_domain::java;
use vectispire_domain::list_window::ListWindow;
use vectispire_domain::siem::SecurityEventType;

use crate::connections::actor_name;
use crate::error::ForgeError;
use crate::internal::planner::{
    self, CredentialView, HostCredential, ImportPlanner, ImportRequest, Plan, RefusedImport, Row, SkippedImport,
};
use crate::persistence::{self, LinkRow};
use crate::views::{ForgeRepositoryView, instant, iso_opt};

/// `ForgeSelectionFilters`, as a request spells them.
#[derive(Debug, Clone, Default)]
pub struct Filters {
    pub archived: Option<String>,
    pub forks: Option<String>,
    pub inactive_days: Option<i64>,
    pub language: Option<String>,
    pub visibility: Option<String>,
    pub namespace: Option<String>,
    pub path: Option<String>,
    pub personal: Option<String>,
    pub present: Option<String>,
}

impl Filters {
    fn filter(&self) -> Result<SelectionFilter, Refused> {
        SelectionFilter::parse(&Requested {
            archived: self.archived.as_deref(),
            forks: self.forks.as_deref(),
            inactive_days: self.inactive_days,
            language: self.language.as_deref(),
            visibility: self.visibility.as_deref(),
            namespace: self.namespace.as_deref(),
            path: self.path.as_deref(),
            personal: self.personal.as_deref(),
            present: self.present.as_deref(),
        })
    }
}

/// `ForgeSelectionChange`.
#[derive(Debug, Clone, Default)]
pub struct SelectionChange {
    pub filters: Option<Filters>,
    pub selected: Option<Vec<Option<String>>>,
    pub operation: Option<String>,
    pub forge_ids: Option<Vec<Option<String>>>,
}

/// `ForgeCandidate`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForgeCandidate {
    pub repository: ForgeRepositoryView,
    pub present_as: Vec<i64>,
    pub imported_as: Option<i64>,
    pub selectable: bool,
    pub not_selectable: Option<&'static str>,
    pub offered: bool,
    pub proposed_solution: Option<String>,
    pub proposed_project: Option<String>,
}

/// `ForgeCandidatePage`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidatePage {
    pub discovery_id: i64,
    pub items: Vec<ForgeCandidate>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
    pub listed: i64,
    pub unjudged: serde_json::Map<String, serde_json::Value>,
}

/// `ForgeSelection`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Selection {
    pub discovery_id: i64,
    pub selected: Vec<String>,
    pub count: i64,
    pub dropped: Vec<String>,
}

/// `ForgePlannedTarget`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedTarget {
    pub forge_id: String,
    pub full_path: String,
    pub url: Option<String>,
    pub branch: Option<String>,
    pub credential: CredentialView,
    pub solution: Option<String>,
    pub project: Option<String>,
    pub visible_to: String,
    pub first_scan_not_before: Option<String>,
    pub warning: Option<String>,
}

/// `ForgeSolutionPlan`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SolutionPlan {
    pub name: String,
    pub existing_id: Option<i64>,
}

/// `ForgeProjectPlan`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectPlan {
    pub solution: String,
    pub name: String,
    pub existing_id: Option<i64>,
    pub accounts: i64,
    pub teams: i64,
    pub targets: i64,
}

/// `ForgeFirstScans`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirstScans {
    pub count: i64,
    pub spacing_seconds: i64,
    pub first_at: Option<String>,
    pub last_at: Option<String>,
}

/// `ForgeImportPreview`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    pub connection_id: String,
    pub discovery_id: i64,
    pub targets: Vec<PlannedTarget>,
    pub skipped: Vec<SkippedImport>,
    pub refused: Vec<RefusedImport>,
    pub solutions: Vec<SolutionPlan>,
    pub projects: Vec<ProjectPlan>,
    pub credentials: Vec<HostCredential>,
    pub default_interval_days: i64,
    pub visibility_mode: &'static str,
    pub first_scans: Option<FirstScans>,
}

/// `ForgeImportedTarget`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedTarget {
    pub forge_id: String,
    pub full_path: String,
    pub repository_id: i64,
    pub url: String,
    pub solution: Option<String>,
    pub project: Option<String>,
    pub first_scan_id: Option<i64>,
    pub first_scan_not_before: Option<String>,
}

/// `ForgeImportResult`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub connection_id: String,
    pub discovery_id: i64,
    pub created: Vec<ImportedTarget>,
    pub skipped: Vec<SkippedImport>,
    pub solutions_created: Vec<String>,
    pub projects_created: Vec<String>,
    pub first_scans: Option<FirstScans>,
}

/// The services: the selection reads, the import writes.
pub struct ForgeImports {
    planner: ImportPlanner,
    targets: Arc<Targets>,
    audit: Arc<AuditLog>,
}

impl std::fmt::Debug for ForgeImports {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ForgeImports").finish_non_exhaustive()
    }
}

/// How many times an import that lost a race is planned again.
const ATTEMPTS: usize = 3;

fn candidate(row: &Row) -> Candidate<'_> {
    let repository = &row.repository;
    Candidate {
        archived: repository.archived,
        fork: repository.fork,
        last_activity_at: repository.last_activity_at.map(instant),
        language: repository.language.as_deref(),
        visibility: repository.visibility.as_deref(),
        namespace_path: &repository.namespace_path,
        full_path: &repository.full_path,
        personal: repository.personal,
        present: row.not_selectable.is_some() && (row.imported_as.is_some() || !row.present_as.is_empty()),
    }
}

/// Offered ticked: selectable, kept by the default filters, and not in a personal namespace (answer 7).
fn offered(row: &Row, now: vectispire_domain::instant::Instant) -> bool {
    row.not_selectable.is_none()
        && !row.repository.personal
        && SelectionFilter::default_filter().judge(&candidate(row), now).matches
}

fn first_scans(plan: &Plan) -> Option<FirstScans> {
    plan.spacing_seconds.map(|gap| FirstScans {
        count: i64::try_from(plan.targets.len()).unwrap_or(i64::MAX),
        spacing_seconds: gap,
        first_at: plan.targets.first().and_then(|target| iso_opt(target.first_scan_not_before)),
        last_at: plan.targets.last().and_then(|target| iso_opt(target.first_scan_not_before)),
    })
}

fn projects(plan: &Plan) -> Vec<ProjectPlan> {
    plan.projects
        .iter()
        .map(|project| ProjectPlan {
            solution: project.solution.clone(),
            name: project.name.clone(),
            existing_id: project.existing.as_ref().map(|existing| existing.id),
            accounts: project.reach.0,
            teams: project.reach.1,
            targets: project.targets,
        })
        .collect()
}

impl ForgeImports {
    pub(crate) fn new(planner: ImportPlanner, targets: Arc<Targets>, audit: Arc<AuditLog>) -> ForgeImports {
        ForgeImports { planner, targets, audit }
    }

    /// A page of the discovery's repositories the filters match, by full path.
    pub async fn candidates(
        &self,
        connection_id: &str,
        discovery_id: i64,
        filters: &Filters,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<CandidatePage, ForgeError> {
        let source = self.planner.source(connection_id, Some(discovery_id)).await?;
        let filter = filters.filter()?;
        let window = ListWindow::new(limit.unwrap_or(100), offset.unwrap_or(0)).map_err(ForgeError::InvalidInput)?;
        let now = instant(self.planner.clock.now());
        let rows = self.planner.rows(&source).await?;
        let mut unjudged: BTreeMap<Judged, i64> = BTreeMap::new();
        let mut matching = Vec::new();
        for row in &rows {
            let verdict = filter.judge(&candidate(row), now);
            for judged in verdict.unjudged {
                *unjudged.entry(judged).or_insert(0) += 1;
            }
            if verdict.matches {
                matching.push(ForgeCandidate {
                    repository: ForgeRepositoryView::of(&row.repository),
                    present_as: row.present_as.clone(),
                    imported_as: row.imported_as,
                    selectable: row.not_selectable.is_none(),
                    not_selectable: row.not_selectable.map(|skip| skip.wire_name()),
                    offered: offered(row, now),
                    proposed_solution: row.proposed.solution.clone(),
                    proposed_project: row.proposed.project.clone(),
                });
            }
        }
        Ok(CandidatePage {
            discovery_id: source.discovery.id,
            total: i64::try_from(matching.len()).unwrap_or(i64::MAX),
            items: window.of(&matching),
            limit: window.limit,
            offset: window.offset,
            listed: i64::try_from(rows.len()).unwrap_or(i64::MAX),
            unjudged: unjudged
                .into_iter()
                .map(|(judged, count)| (judged.wire_name().to_owned(), serde_json::Value::from(count)))
                .collect(),
        })
    }

    /// The selection after one operation, over what the filters match; only a selectable repository stays ticked.
    pub async fn select(
        &self,
        connection_id: &str,
        discovery_id: i64,
        change: Option<SelectionChange>,
    ) -> Result<Selection, ForgeError> {
        let Some(change) = change else {
            return Err(ForgeError::InvalidInput(
                "Say how the selection changes: an operation, and the forge ids ticked so far.".into(),
            ));
        };
        let source = self.planner.source(connection_id, Some(discovery_id)).await?;
        let operation = operation_of(change.operation.as_deref())?;
        let filter = change.filters.clone().unwrap_or_default().filter()?;
        let selected = planner::forge_ids(change.selected.as_deref(), planner::MAX_SELECTION, "A selection")?;
        let named = planner::forge_ids(change.forge_ids.as_deref(), planner::MAX_SELECTION, "A selection")?;
        let names_ids = matches!(operation, Operation::Add | Operation::Remove);
        if names_ids == named.is_empty() {
            return Err(ForgeError::InvalidInput(if names_ids {
                format!("Name the forge ids to {}.", operation.name())
            } else {
                format!("forgeIds is for add and remove; {} applies to what the filters match.", operation.name())
            }));
        }
        let now = instant(self.planner.clock.now());
        let rows = self.planner.rows(&source).await?;
        let mut result: Vec<String> = if operation == Operation::Proposed { Vec::new() } else { selected.clone() };
        for row in &rows {
            let id = &row.repository.forge_id;
            let matches = filter.judge(&candidate(row), now).matches;
            let has = result.contains(id);
            match operation {
                Operation::Proposed if matches && !row.repository.personal && !has => result.push(id.clone()),
                Operation::All if matches && !has => result.push(id.clone()),
                Operation::None if matches => result.retain(|known| known != id),
                Operation::Invert if matches => {
                    if has {
                        result.retain(|known| known != id);
                    } else {
                        result.push(id.clone());
                    }
                }
                Operation::Add if named.contains(id) && !has => result.push(id.clone()),
                Operation::Remove if named.contains(id) => result.retain(|known| known != id),
                _ => {}
            }
        }
        // Kept in the table's order, and only what may be ticked.
        let mut ordered = Vec::new();
        let mut selectable_ids = BTreeSet::new();
        for row in rows.iter().filter(|row| row.not_selectable.is_none()) {
            selectable_ids.insert(row.repository.forge_id.clone());
            if result.contains(&row.repository.forge_id) {
                ordered.push(row.repository.forge_id.clone());
            }
        }
        let mut asked = selected.clone();
        if operation == Operation::Add {
            for id in &named {
                if !asked.contains(id) {
                    asked.push(id.clone());
                }
            }
        }
        let dropped: Vec<String> = asked
            .into_iter()
            .filter(|id| !selectable_ids.contains(id) && !(operation == Operation::Remove && named.contains(id)))
            .collect();
        Ok(Selection {
            discovery_id: source.discovery.id,
            count: i64::try_from(ordered.len()).unwrap_or(i64::MAX),
            selected: ordered,
            dropped,
        })
    }

    /// What the import of this request would do; nothing is written.
    pub async fn preview(
        &self,
        connection_id: &str,
        request: Option<&ImportRequest>,
    ) -> Result<ImportPreview, ForgeError> {
        let source = self.planner.source(connection_id, request.and_then(|request| request.discovery_id)).await?;
        let plan = self.planner.plan(source, request).await?;
        let targets = plan
            .targets
            .iter()
            .map(|target| PlannedTarget {
                forge_id: target.repository.forge_id.clone(),
                full_path: target.repository.full_path.clone(),
                url: target.changes.url.clone(),
                branch: target.changes.branch.clone(),
                credential: target.credential.clone(),
                solution: target.placement.solution.clone(),
                project: target.placement.project.clone(),
                visible_to: plan.visible_to(&target.placement),
                first_scan_not_before: iso_opt(target.first_scan_not_before),
                warning: target.warning.clone(),
            })
            .collect();
        Ok(ImportPreview {
            connection_id: plan.source.connection.id.clone(),
            discovery_id: plan.source.discovery.id,
            targets,
            skipped: plan.skipped.clone(),
            refused: plan.refused.clone(),
            solutions: plan
                .solutions
                .iter()
                .map(|solution| SolutionPlan {
                    name: solution.name.clone(),
                    existing_id: solution.existing.as_ref().map(|existing| existing.id),
                })
                .collect(),
            projects: projects(&plan),
            credentials: plan.credentials.clone(),
            default_interval_days: plan.default_interval_days,
            visibility_mode: plan.visibility_mode,
            first_scans: first_scans(&plan),
        })
    }

    /// Imports the request's repositories.
    pub async fn apply(
        &self,
        connection_id: &str,
        request: Option<&ImportRequest>,
        actor: &RequestActor,
    ) -> Result<ImportResult, ForgeError> {
        let mut attempt = 1;
        loop {
            let mut tried = None;
            match self.attempt(connection_id, request, actor, &mut tried).await {
                Ok((plan, created, solutions, projects)) => {
                    self.record(&plan, &created, &solutions, &projects, actor).await;
                    return Ok(ImportResult {
                        connection_id: plan.source.connection.id.clone(),
                        discovery_id: plan.source.discovery.id,
                        created,
                        skipped: plan.skipped.clone(),
                        solutions_created: solutions,
                        projects_created: projects,
                        first_scans: first_scans(&plan),
                    });
                }
                Err(failed) => {
                    let Some(tried) = tried else {
                        return Err(failed);
                    };
                    if attempt >= ATTEMPTS || !self.raced(connection_id, request, &tried).await {
                        return Err(failed);
                    }
                    tracing::info!(
                        "Forge import from connection {connection_id} lost a race (attempt {attempt}): planned again \
                         from what is committed: {failed}"
                    );
                    attempt += 1;
                }
            }
        }
    }

    #[allow(clippy::type_complexity)]
    async fn attempt(
        &self,
        connection_id: &str,
        request: Option<&ImportRequest>,
        actor: &RequestActor,
        tried: &mut Option<Plan>,
    ) -> Result<(Plan, Vec<ImportedTarget>, Vec<String>, Vec<String>), ForgeError> {
        let source = self.planner.source(connection_id, request.and_then(|request| request.discovery_id)).await?;
        let plan = self.planner.plan(source, request).await?;
        *tried = Some(plan.clone());
        refuse_if_any_refused(&plan.refused)?;
        let unexpected = |error: vectispire_cp_targets::TargetError| match error {
            vectispire_cp_targets::TargetError::Invalid(message) => ForgeError::InvalidInput(message),
            other => ForgeError::Unexpected(other.to_string()),
        };
        let mut batch = self.targets.import_batch(actor).await.map_err(unexpected)?;
        let mut solution_ids: HashMap<String, i64> = HashMap::new();
        let mut project_ids: HashMap<String, i64> = HashMap::new();
        let mut solutions_created = Vec::new();
        let mut projects_created = Vec::new();
        for planned in &plan.solutions {
            let solution = batch.solution(&planned.name).await.map_err(unexpected)?;
            solution_ids.insert(java::to_lower_root(&planned.name), solution.view.id);
            if solution.created {
                solutions_created.push(solution.view.name.clone());
            }
        }
        for planned in &plan.projects {
            let solution_id = solution_ids.get(&java::to_lower_root(&planned.solution)).copied().unwrap_or_default();
            let project = batch.project(solution_id, &planned.name).await.map_err(unexpected)?;
            project_ids.insert(key(&planned.solution, &planned.name), project.view.id);
            if project.created {
                projects_created.push(format!("{} / {}", planned.solution, project.view.name));
            }
        }
        // An entry's description holds 255 characters: the URL first, then where it came from.
        let origin = format!(
            " — imported from connection {}, discovery {}",
            bounded_text::clip(Some(&plan.source.connection.name), 40).unwrap_or_default(),
            plan.source.discovery.id
        );
        let importer = actor_name(actor);
        let mut created = Vec::new();
        let mut links = Vec::new();
        let mut scans = Vec::new();
        for target in &plan.targets {
            let placement = &target.placement;
            let project_id = match (&placement.solution, &placement.project) {
                (Some(solution), Some(project)) => project_ids.get(&key(solution, project)).copied(),
                _ => None,
            };
            let provenance = format!(
                "{origin}, forge id {}{}",
                target.repository.forge_id,
                match (&placement.solution, &placement.project) {
                    (Some(solution), Some(project)) => format!(", into project {solution} / {project}"),
                    _ => String::new(),
                }
            );
            let repository =
                batch.repository(&target.changes, project_id, plan.at, &provenance).await.map_err(unexpected)?;
            links.push(LinkRow {
                id: 0,
                repository_id: repository.id,
                connection_id: plan.source.connection.id.clone(),
                forge_id: target.repository.forge_id.clone(),
                discovery_id: plan.source.discovery.id,
                imported_at: plan.at,
                imported_by: importer.clone(),
            });
            if let Some(not_before) = target.first_scan_not_before {
                scans.push((created.len(), repository.clone(), not_before));
            }
            created.push(ImportedTarget {
                forge_id: target.repository.forge_id.clone(),
                full_path: target.repository.full_path.clone(),
                repository_id: repository.id,
                url: repository.url.clone(),
                solution: placement.solution.clone(),
                project: placement.project.clone(),
                first_scan_id: None,
                first_scan_not_before: iso_opt(target.first_scan_not_before),
            });
        }
        // In the batch's transaction: a link and its target commit together or not at all.
        for link in &links {
            persistence::insert_link(batch.transaction(), link).await.map_err(ForgeError::from)?;
        }
        batch.commit().await.map_err(unexpected)?;
        // The first scans after the commit: the scans' owner writes in a transaction of its own, which would wait on the
        // batch's uncommitted rows. Java queued them inside; a scan refused now leaves the target to its schedule.
        for (index, repository, not_before) in scans {
            match self.targets.first_scan(&repository, not_before).await {
                Ok(queued) => created[index].first_scan_id = Some(queued.id),
                Err(failure) => {
                    tracing::warn!("The first scan of imported repository {} was not queued: {failure}", repository.id)
                }
            }
        }
        Ok((plan, created, solutions_created, projects_created))
    }

    /// Whether what is committed now makes the request create less than the attempt that failed.
    async fn raced(&self, connection_id: &str, request: Option<&ImportRequest>, failed: &Plan) -> bool {
        let Ok(source) = self.planner.source(connection_id, request.and_then(|request| request.discovery_id)).await
        else {
            return false;
        };
        match self.planner.plan(source, request).await {
            Ok(now) => !planner::same_creations(failed, &now),
            Err(_) => false,
        }
    }

    /// The summary entry, after the commit; signalled when the import created something.
    async fn record(
        &self,
        plan: &Plan,
        created: &[ImportedTarget],
        solutions: &[String],
        projects: &[String],
        actor: &RequestActor,
    ) {
        let mut skipped: BTreeMap<usize, (&str, i64)> = BTreeMap::new();
        for repository in &plan.skipped {
            let order = SKIP_ORDER.iter().position(|reason| *reason == repository.reason).unwrap_or(SKIP_ORDER.len());
            skipped.entry(order).or_insert((repository.reason, 0)).1 += 1;
        }
        let description = format!(
            "Forge import, connection {}, discovery {}: {} target(s) created, {} skipped{}, {} solution(s) and {} \
             project(s) created, first scans {}, no grant; credentials {}",
            bounded_text::clip(Some(&plan.source.connection.name), 40).unwrap_or_default(),
            plan.source.discovery.id,
            created.len(),
            plan.skipped.len(),
            if skipped.is_empty() {
                String::new()
            } else {
                format!(
                    " ({})",
                    skipped.values().map(|(reason, count)| format!("{count} {reason}")).collect::<Vec<_>>().join(", ")
                )
            },
            solutions.len(),
            projects.len(),
            plan.spacing_seconds.map_or_else(|| "none".to_owned(), |gap| format!("{} {gap} s apart", created.len())),
            if plan.credentials.is_empty() {
                "none".to_owned()
            } else {
                plan.credentials
                    .iter()
                    .map(|host| format!("{} {}", host.host, host.credential.kind))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        );
        let entry = actor.entry(AuditOperation::ForgeImportApplied, &plan.source.connection.id, &description);
        self.audit
            .record(if created.is_empty() {
                entry
            } else {
                entry.signalling(Signal(SecurityEventType::ForgeImportApplied.wire_name()))
            })
            .await;
    }
}

/// `ImportSkip`'s declaration order, which an `EnumMap` iterates.
const SKIP_ORDER: [&str; 5] =
    ["already_imported", "already_present", "no_default_branch", "no_clone_url", "duplicate_in_selection"];

fn refuse_if_any_refused(refused: &[RefusedImport]) -> Result<(), ForgeError> {
    if refused.is_empty() {
        return Ok(());
    }
    let first = refused
        .iter()
        .take(3)
        .map(|repository| format!("{}: {}", repository.full_path, repository.refusal))
        .collect::<Vec<_>>()
        .join(" ");
    Err(ForgeError::InvalidInput(format!(
        "{} of the selected repositories would be refused — {first}{} Untick them or change what the preview names, \
         then import again.",
        refused.len(),
        if refused.len() > 3 { " …" } else { "" }
    )))
}

fn key(solution: &str, project: &str) -> String {
    format!("{}\n{}", java::to_lower_root(solution), java::to_lower_root(project))
}

/// A selection's operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    Proposed,
    All,
    None,
    Invert,
    Add,
    Remove,
}

impl Operation {
    const ALL: [Operation; 6] =
        [Operation::Proposed, Operation::All, Operation::None, Operation::Invert, Operation::Add, Operation::Remove];

    const fn name(self) -> &'static str {
        match self {
            Operation::Proposed => "proposed",
            Operation::All => "all",
            Operation::None => "none",
            Operation::Invert => "invert",
            Operation::Add => "add",
            Operation::Remove => "remove",
        }
    }
}

fn operation_of(raw: Option<&str>) -> Result<Operation, ForgeError> {
    let wanted = java::to_lower_root(java::trim(raw.unwrap_or("")));
    Operation::ALL.into_iter().find(|operation| operation.name() == wanted).ok_or_else(|| {
        ForgeError::InvalidInput(format!(
            "\"{}\" is not a selection operation: proposed, all, none, invert, add or remove.",
            bounded_text::clip(Some(java::trim(raw.unwrap_or(""))), 40).unwrap_or_default()
        ))
    })
}
