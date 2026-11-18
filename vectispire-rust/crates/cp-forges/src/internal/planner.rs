//! `ImportPlanner`: a discovery's snapshot as the selection and the import read it, and the plan of an import — which
//! repositories become targets, filed where, cloned how, scanned when, and which are skipped and why (decision 0037
//! §4–5). **One planner for the preview and the import**: the import plans again inside its transaction. **"Already
//! present" is one rule**, the repository form's: the identity of the HTTPS *or* SSH clone URL equals an existing
//! target's, whatever its branch and sub-path.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::Db;
use vectispire_cp_settings::{Setting, Settings};
use vectispire_cp_targets::Targets;
use vectispire_cp_targets::repositories::Changes;
use vectispire_cp_targets::views::{ProjectView, SolutionView};
use vectispire_domain::bounded_text;
use vectispire_domain::forges::mapping::{ImportMapping, Placement, Rule};
use vectispire_domain::forges::{DiscoveredRepository, ForgeKind, ImportSkip};
use vectispire_domain::java;
use vectispire_domain::repository_url;

use super::integrations::ForgeIntegrations;
use crate::discoveries::{NOT_SELECTABLE, SUPERSEDED};
use crate::error::{ForgeError, connection_not_found};
use crate::persistence::{self, ConnectionRow, DiscoveryRow, RepositoryRow, StoreError};

/// The most repositories one import creates, in one transaction (answer 8).
pub(crate) const MAX_IMPORT: usize = 1_000;
/// The most forge ids a selection carries: a discovery's own bound.
pub(crate) const MAX_SELECTION: usize = 20_000;
pub(crate) const DEFAULT_SPACING_SECONDS: i64 = 60;
pub(crate) const MIN_SPACING_SECONDS: i64 = 10;
pub(crate) const MAX_SPACING_SECONDS: i64 = 600;
/// The width of a target's name column: a full path longer than it leaves the name to the URL.
const TARGET_NAME_LENGTH: usize = 255;
const SELECTABLE_STATES: [&str; 2] = ["completed", "partial"];

/// A discovery the selection may read, with its connection.
#[derive(Debug, Clone)]
pub(crate) struct Source {
    pub connection: ConnectionRow,
    pub discovery: DiscoveryRow,
    pub kind: ForgeKind,
}

/// One repository of the discovery, as the selection judges it.
#[derive(Debug, Clone)]
pub(crate) struct Row {
    pub repository: RepositoryRow,
    pub present_as: Vec<i64>,
    pub imported_as: Option<i64>,
    pub not_selectable: Option<ImportSkip>,
    pub proposed: Placement,
}

/// What the request asks for, as `ForgeImportRequest` carries it.
#[derive(Debug, Clone, Default)]
pub struct ImportRequest {
    pub discovery_id: Option<i64>,
    pub forge_ids: Option<Vec<Option<String>>>,
    pub mapping: Option<Vec<Option<Rule>>>,
    pub credentials: Option<Vec<Option<CredentialChoice>>>,
    pub first_scan: Option<bool>,
    pub spacing_seconds: Option<i64>,
    pub required_agent_label: Option<String>,
}

/// `ForgeCredentialChoice`.
#[derive(Debug, Clone, Default)]
pub struct CredentialChoice {
    pub host: Option<String>,
    pub ssh_key_id: Option<String>,
    pub https_token_id: Option<String>,
}

/// `ForgeCredentialView`: never the secret.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CredentialView {
    pub kind: &'static str,
    pub id: Option<String>,
    pub name: Option<String>,
}

/// `ForgeHostCredential`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HostCredential {
    pub host: String,
    pub credential: CredentialView,
    pub proposed: bool,
    pub repositories: i64,
}

/// `ForgeSkippedImport`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedImport {
    pub forge_id: String,
    pub full_path: String,
    pub reason: &'static str,
    pub repository_ids: Vec<i64>,
}

/// `ForgeRefusedImport`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefusedImport {
    pub forge_id: String,
    pub full_path: String,
    pub refusal: String,
}

/// One target the import creates.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    pub repository: RepositoryRow,
    pub changes: Changes,
    pub credential: CredentialView,
    pub placement: Placement,
    pub first_scan_not_before: Option<OffsetDateTime>,
    pub warning: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct PlannedSolution {
    pub name: String,
    pub existing: Option<SolutionView>,
}

#[derive(Debug, Clone)]
pub(crate) struct PlannedProject {
    pub solution: String,
    pub name: String,
    pub existing: Option<ProjectView>,
    /// How many accounts and teams a grant on the project reaches.
    pub reach: (i64, i64),
    pub targets: i64,
}

/// What an import would do.
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub source: Source,
    pub at: OffsetDateTime,
    pub targets: Vec<Target>,
    pub skipped: Vec<SkippedImport>,
    pub refused: Vec<RefusedImport>,
    pub solutions: Vec<PlannedSolution>,
    pub projects: Vec<PlannedProject>,
    pub credentials: Vec<HostCredential>,
    pub spacing_seconds: Option<i64>,
    pub default_interval_days: i64,
    /// `everyone` or `assigned`.
    pub visibility_mode: &'static str,
}

impl Plan {
    /// What the plan creates, as a set a second reading compares.
    pub(crate) fn creations(&self) -> BTreeSet<String> {
        let mut creations = BTreeSet::new();
        for target in &self.targets {
            creations.insert(format!("repository {}", target.repository.forge_id));
        }
        for solution in self.solutions.iter().filter(|solution| solution.existing.is_none()) {
            creations.insert(format!("solution {}", java::to_lower_root(&solution.name)));
        }
        for project in self.projects.iter().filter(|project| project.existing.is_none()) {
            creations.insert(format!(
                "project {} / {}",
                java::to_lower_root(&project.solution),
                java::to_lower_root(&project.name)
            ));
        }
        creations
    }

    /// Who will see a target filed there, in words.
    pub(crate) fn visible_to(&self, placement: &Placement) -> String {
        if self.visibility_mode == "everyone" {
            return "every signed-in account: visibility is not restricted on this installation".into();
        }
        let base = "administrators and the roles that see the whole estate";
        let (Some(solution), Some(project)) = (&placement.solution, &placement.project) else {
            return format!("{base} — it is filed into no project");
        };
        let Some(planned) = self.projects.iter().find(|planned| {
            java::compare_ignore_case(&planned.solution, solution).is_eq()
                && java::compare_ignore_case(&planned.name, project).is_eq()
        }) else {
            return format!("{base} — it is filed into no project");
        };
        let name = format!("{} / {}", planned.solution, planned.name);
        if planned.existing.is_none() {
            return format!("{base} only — project {name} is new and nobody holds a grant on it yet");
        }
        if planned.reach == (0, 0) {
            return format!("{base} only — nobody holds a grant on project {name}");
        }
        format!("{base}, and the {} account(s) and {} team(s) granted project {name}", planned.reach.0, planned.reach.1)
    }
}

/// The planner.
#[derive(Clone)]
pub(crate) struct ImportPlanner {
    pub(crate) db: Db,
    pub(crate) targets: Arc<Targets>,
    pub(crate) settings: Settings,
    pub(crate) integrations: ForgeIntegrations,
    pub(crate) clock: Arc<dyn vectispire_cp_targets::Clock>,
}

fn unexpected(error: impl std::fmt::Display) -> ForgeError {
    ForgeError::Unexpected(error.to_string())
}

impl ImportPlanner {
    /// The discovery to select from: the connection's latest that ended with something to choose — completed, or
    /// partial. The connection's 404, then the discovery's; a run in another state, or one superseded, a 409.
    pub(crate) async fn source(&self, connection_id: &str, discovery_id: Option<i64>) -> Result<Source, ForgeError> {
        let mut tx = persistence::read(&self.db).await?;
        let connection = persistence::connection(&mut tx, connection_id).await?.ok_or_else(connection_not_found)?;
        let Some(discovery_id) = discovery_id else {
            return Err(ForgeError::InvalidInput("Name the discovery to import from: discoveryId.".into()));
        };
        let discovery = persistence::discovery_of(&mut tx, discovery_id, connection_id)
            .await?
            .ok_or_else(|| ForgeError::NotFound(format!("Forge discovery {discovery_id} not found.")))?;
        if !SELECTABLE_STATES.contains(&discovery.state.as_str()) {
            return Err(ForgeError::Conflict {
                cause: NOT_SELECTABLE,
                message: format!(
                    "Discovery {discovery_id} is {}: repositories are selected from a discovery that completed, or \
                     ended partial.",
                    discovery.state
                ),
                members: vec![("state", serde_json::Value::from(discovery.state.clone()))],
            });
        }
        let latest = persistence::latest_discovery_in(&mut tx, connection_id, &SELECTABLE_STATES).await?;
        tx.commit().await.map_err(StoreError::from)?;
        if let Some(latest) = latest.filter(|latest| latest.id != discovery.id) {
            return Err(ForgeError::Conflict {
                cause: SUPERSEDED,
                message: format!("Discovery {} has ended since discovery {discovery_id}: select from it.", latest.id),
                members: vec![("latestDiscoveryId", serde_json::Value::from(latest.id))],
            });
        }
        let kind = ForgeKind::parse(Some(&connection.kind))?;
        Ok(Source { connection, discovery, kind })
    }

    /// Every repository the discovery listed, by full path.
    pub(crate) async fn rows(&self, source: &Source) -> Result<Vec<Row>, ForgeError> {
        let mut tx = persistence::read(&self.db).await?;
        let listed = persistence::listed_by(&mut tx, &source.connection.id, source.discovery.id).await?;
        let linked = persistence::links_of(&mut tx, &source.connection.id, None).await?;
        tx.commit().await.map_err(StoreError::from)?;
        self.rows_of(source, listed, &linked).await
    }

    async fn rows_of(
        &self,
        source: &Source,
        mut listed: Vec<RepositoryRow>,
        linked: &[persistence::LinkRow],
    ) -> Result<Vec<Row>, ForgeError> {
        let imported_as: HashMap<&str, i64> =
            linked.iter().map(|link| (link.forge_id.as_str(), link.repository_id)).collect();
        let identities: Vec<String> =
            listed.iter().flat_map(identities_of).collect::<BTreeSet<_>>().into_iter().collect();
        let present = self.targets.present_by_identity(&identities).await.map_err(unexpected)?;
        // `Comparator.comparing(fullPath.toLowerCase).thenComparing(forgeId)`, by UTF-16 unit.
        listed.sort_by(|left, right| {
            java::compare_utf16(&java::to_lower_root(&left.full_path), &java::to_lower_root(&right.full_path))
                .then_with(|| java::compare_utf16(&left.forge_id, &right.forge_id))
        });
        Ok(listed
            .into_iter()
            .map(|row| {
                let present_as: Vec<i64> = identities_of(&row)
                    .iter()
                    .flat_map(|identity| present.get(identity).cloned().unwrap_or_default())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                let imported = imported_as.get(row.forge_id.as_str()).copied();
                let skip = if imported.is_some() {
                    Some(ImportSkip::AlreadyImported)
                } else if !present_as.is_empty() {
                    Some(ImportSkip::AlreadyPresent)
                } else if row.default_branch.is_none() {
                    Some(ImportSkip::NoDefaultBranch)
                } else if row.http_url.is_none() && row.ssh_url.is_none() {
                    Some(ImportSkip::NoCloneUrl)
                } else {
                    None
                };
                let proposed = ImportMapping::proposed(source.kind, &row.namespace_path, &row.name, row.personal);
                Row { repository: row, present_as, imported_as: imported, not_selectable: skip, proposed }
            })
            .collect())
    }

    /// Plans the import the request asks for, from the source's snapshot as it reads now.
    pub(crate) async fn plan(&self, source: Source, request: Option<&ImportRequest>) -> Result<Plan, ForgeError> {
        self.integrations.require_enabled(source.kind).await?;
        let Some(request) = request else {
            return Err(ForgeError::InvalidInput(
                "Describe the import: the discovery, the repositories and their credentials.".into(),
            ));
        };
        let wanted = forge_ids(request.forge_ids.as_deref(), MAX_IMPORT, "An import")?;
        if wanted.is_empty() {
            return Err(ForgeError::InvalidInput("Select at least one repository to import.".into()));
        }
        let mapping = ImportMapping::of(request.mapping.clone())?;
        let spacing = spacing(request.first_scan, request.spacing_seconds)?;
        let tokens = self.tokens_by_host().await?;
        let key_names = self.key_names().await?;
        let choices = choices(request.credentials.as_deref(), &tokens, &key_names)?;
        let mut tx = persistence::read(&self.db).await?;
        let listed: Vec<RepositoryRow> = persistence::listed_by(&mut tx, &source.connection.id, source.discovery.id)
            .await?
            .into_iter()
            .filter(|row| wanted.contains(&row.forge_id))
            .collect();
        if listed.len() < wanted.len() {
            let found: BTreeSet<&str> = listed.iter().map(|row| row.forge_id.as_str()).collect();
            let missing: Vec<&str> =
                wanted.iter().map(String::as_str).filter(|id| !found.contains(id)).take(5).collect();
            let absent = wanted.len() - listed.len();
            return Err(ForgeError::InvalidInput(format!(
                "{absent} of the selected repositories are not listed by discovery {}: {}{}.",
                source.discovery.id,
                missing.join(", "),
                if absent > missing.len() { ", …" } else { "" }
            )));
        }
        let wanted_ids: Vec<String> = wanted.clone();
        let linked = persistence::links_of(&mut tx, &source.connection.id, Some(&wanted_ids)).await?;
        tx.commit().await.map_err(StoreError::from)?;
        let rows = self.rows_of(&source, listed, &linked).await?;
        let at = self.clock.now();
        let forge_host = connection_host(&source.connection);
        let mut planned = Vec::new();
        let mut skipped = Vec::new();
        let mut refused = Vec::new();
        let mut hosts: Vec<(String, Choice, CredentialView, i64)> = Vec::new();
        let mut identities: BTreeSet<String> = BTreeSet::new();
        for row in rows {
            let repository = &row.repository;
            if let Some(skip) = row.not_selectable {
                skipped.push(SkippedImport {
                    forge_id: repository.forge_id.clone(),
                    full_path: repository.full_path.clone(),
                    reason: skip.wire_name(),
                    repository_ids: row.imported_as.map_or_else(|| row.present_as.clone(), |id| vec![id]),
                });
                continue;
            }
            let own = identities_of(repository);
            if own.iter().any(|identity| identities.contains(identity)) {
                skipped.push(SkippedImport {
                    forge_id: repository.forge_id.clone(),
                    full_path: repository.full_path.clone(),
                    reason: ImportSkip::DuplicateInSelection.wire_name(),
                    repository_ids: Vec::new(),
                });
                continue;
            }
            identities.extend(own);
            let host = host_of(repository);
            let choice = choices.get(&host).cloned().unwrap_or_else(|| proposal(&host, &tokens));
            let url = if choice.ssh_key_id.is_some() { &repository.ssh_url } else { &repository.http_url };
            let Some(url) = url.clone() else {
                skipped.push(SkippedImport {
                    forge_id: repository.forge_id.clone(),
                    full_path: repository.full_path.clone(),
                    reason: ImportSkip::NoCloneUrl.wire_name(),
                    repository_ids: Vec::new(),
                });
                continue;
            };
            if let Some(elsewhere) = elsewhere(&url, &forge_host) {
                refused.push(RefusedImport {
                    forge_id: repository.forge_id.clone(),
                    full_path: repository.full_path.clone(),
                    refusal: elsewhere,
                });
                continue;
            }
            let credential = credential_view(&choice, &key_names, &tokens);
            match hosts.iter_mut().find(|(known, ..)| *known == host) {
                Some((_, _, _, count)) => *count += 1,
                None => hosts.push((host.clone(), choice.clone(), credential.clone(), 1)),
            }
            let placed = mapping.place(
                source.kind,
                &repository.forge_id,
                &repository.namespace_path,
                &repository.name,
                repository.personal,
            );
            let changes = Changes {
                url: Some(url),
                branch: repository.default_branch.clone(),
                name: (java::utf16_len(&repository.full_path) <= TARGET_NAME_LENGTH)
                    .then(|| repository.full_path.clone()),
                sub_path: None,
                scan_interval_minutes: None,
                scan_cron: None,
                required_agent_label: request.required_agent_label.clone(),
                ssh_key_id: choice.ssh_key_id.map(|id| id.to_string()),
                tier: None,
                https_token_id: choice.https_token_id.map(|id| id.to_string()),
                scan_manual_only: None,
            };
            let refusal = match placed.refusal {
                Some(refusal) => Some(refusal),
                None => self.targets.repository_refusal(&changes).await.map_err(unexpected)?,
            };
            if let Some(refusal) = refusal {
                refused.push(RefusedImport {
                    forge_id: repository.forge_id.clone(),
                    full_path: repository.full_path.clone(),
                    refusal,
                });
                continue;
            }
            planned.push(Target {
                repository: repository.clone(),
                changes,
                credential,
                placement: placed.placement,
                first_scan_not_before: None,
                warning: warning(repository, &choice),
            });
        }
        let (solutions, projects) = self.place(&planned).await?;
        // The k-th new target's first scan waits k spacings.
        for (k, target) in planned.iter_mut().enumerate() {
            target.first_scan_not_before = spacing
                .map(|gap| at + time::Duration::seconds(gap.saturating_mul(i64::try_from(k).unwrap_or(i64::MAX))));
        }
        let credentials = hosts
            .into_iter()
            .map(|(host, choice, credential, repositories)| HostCredential {
                host,
                credential,
                proposed: choice.proposed,
                repositories,
            })
            .collect();
        let default_interval_days =
            i64::from(self.settings.as_int(Setting::ScanDefaultIntervalDays).await.map_err(unexpected)?);
        let visibility_mode = self.targets.visibility_mode().await.map_err(unexpected)?.wire_name();
        Ok(Plan {
            source,
            at,
            targets: planned,
            skipped,
            refused,
            solutions,
            projects,
            credentials,
            spacing_seconds: spacing,
            default_interval_days,
            visibility_mode,
        })
    }

    /// The solutions and projects the targets are filed into, each once, compared case aside.
    async fn place(&self, planned: &[Target]) -> Result<(Vec<PlannedSolution>, Vec<PlannedProject>), ForgeError> {
        let mut solutions: Vec<(String, PlannedSolution)> = Vec::new();
        let mut projects: Vec<(String, String, String)> = Vec::new();
        let mut counts: HashMap<String, i64> = HashMap::new();
        for target in planned {
            let (Some(solution_name), Some(project_name)) = (&target.placement.solution, &target.placement.project)
            else {
                continue;
            };
            let solution_key = java::to_lower_root(solution_name);
            if !solutions.iter().any(|(key, _)| *key == solution_key) {
                let existing = self.targets.solution_named(solution_name).await.map_err(unexpected)?;
                let name = existing.as_ref().map_or_else(|| solution_name.clone(), |existing| existing.name.clone());
                solutions.push((solution_key.clone(), PlannedSolution { name, existing }));
            }
            let solution = &solutions
                .iter()
                .find(|(key, _)| *key == solution_key)
                .map(|(_, s)| s.name.clone())
                .unwrap_or_default();
            let project_key = format!("{solution_key}\n{}", java::to_lower_root(project_name));
            if !projects.iter().any(|(key, ..)| *key == project_key) {
                projects.push((project_key.clone(), solution.clone(), project_name.clone()));
            }
            *counts.entry(project_key).or_insert(0) += 1;
        }
        let mut existing_projects: Vec<(String, Option<ProjectView>)> = Vec::new();
        for (key, _, name) in &projects {
            let solution_key = key.split('\n').next().unwrap_or_default();
            let existing =
                match solutions.iter().find(|(known, _)| known == solution_key).and_then(|(_, s)| s.existing.clone()) {
                    Some(solution) => self.targets.project_named(solution.id, name).await.map_err(unexpected)?,
                    None => None,
                };
            existing_projects.push((key.clone(), existing));
        }
        let ids: BTreeSet<i64> =
            existing_projects.iter().filter_map(|(_, project)| project.as_ref().map(|p| p.id)).collect();
        let reach: BTreeMap<i64, (i64, i64)> = self
            .targets
            .grantees(&ids)
            .await
            .map_err(unexpected)?
            .into_iter()
            .map(|(project, grantees)| (project, (grantees.accounts, grantees.teams)))
            .collect();
        let planned_projects = projects
            .into_iter()
            .zip(existing_projects)
            .map(|((key, solution, name), (_, existing))| PlannedProject {
                solution,
                name: existing.as_ref().map_or(name, |project| project.name.clone()),
                reach: existing.as_ref().and_then(|project| reach.get(&project.id).copied()).unwrap_or((0, 0)),
                existing,
                targets: counts.get(&key).copied().unwrap_or(0),
            })
            .collect();
        Ok((solutions.into_iter().map(|(_, solution)| solution).collect(), planned_projects))
    }

    async fn tokens_by_host(&self) -> Result<HashMap<String, Vec<(Uuid, String)>>, ForgeError> {
        let mut by_host: HashMap<String, Vec<(Uuid, String)>> = HashMap::new();
        for token in self.targets.git_tokens(None, None).await.map_err(unexpected)? {
            by_host.entry(java::to_lower_root(&token.host)).or_default().push((token.id, token.name));
        }
        Ok(by_host)
    }

    async fn key_names(&self) -> Result<HashMap<Uuid, String>, ForgeError> {
        Ok(self
            .targets
            .ssh_keys(None, None)
            .await
            .map_err(unexpected)?
            .into_iter()
            .map(|key| (key.id, key.name))
            .collect())
    }
}

/// `forgeIds`: distinct, in the order given, at most `max`.
pub(crate) fn forge_ids(raw: Option<&[Option<String>]>, max: usize, what: &str) -> Result<Vec<String>, ForgeError> {
    let mut ids: Vec<String> = Vec::new();
    for id in raw.unwrap_or_default() {
        let Some(id) = id.as_deref().filter(|id| !java::is_blank(id)) else {
            return Err(ForgeError::InvalidInput("A forge id is empty.".into()));
        };
        let id = bounded_text::within(java::trim(id), DiscoveredRepository::FORGE_ID_LENGTH, "A forge id")?;
        if !ids.iter().any(|known| known == id) {
            ids.push(id.to_owned());
        }
    }
    if ids.len() > max {
        return Err(ForgeError::InvalidInput(format!(
            "{what} takes at most {} repositories; this one names {}. Import a larger selection in several parts.",
            grouped(max),
            grouped(ids.len())
        )));
    }
    Ok(ids)
}

/// `String.format(Locale.ROOT, "%,d", n)`.
fn grouped(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

fn spacing(first_scan: Option<bool>, spacing_seconds: Option<i64>) -> Result<Option<i64>, ForgeError> {
    if let Some(seconds) = spacing_seconds
        && !(MIN_SPACING_SECONDS..=MAX_SPACING_SECONDS).contains(&seconds)
    {
        return Err(ForgeError::InvalidInput(format!(
            "The spacing between first scans is between {MIN_SPACING_SECONDS} seconds and {} minutes.",
            MAX_SPACING_SECONDS / 60
        )));
    }
    if first_scan != Some(true) {
        return Ok(None);
    }
    Ok(Some(spacing_seconds.unwrap_or(DEFAULT_SPACING_SECONDS)))
}

/// A credential for one host: at most one of the two, and whether the proposal chose it.
#[derive(Debug, Clone)]
struct Choice {
    ssh_key_id: Option<Uuid>,
    https_token_id: Option<Uuid>,
    proposed: bool,
}

fn choices(
    raw: Option<&[Option<CredentialChoice>]>,
    tokens: &HashMap<String, Vec<(Uuid, String)>>,
    keys: &HashMap<Uuid, String>,
) -> Result<HashMap<String, Choice>, ForgeError> {
    let mut choices = HashMap::new();
    for choice in raw.unwrap_or_default() {
        let Some(choice) = choice else {
            return Err(ForgeError::InvalidInput("A credential choice is empty.".into()));
        };
        let host = repository_url::normalize_host(choice.host.as_deref().unwrap_or(""))
            .map_err(|invalid| ForgeError::InvalidInput(invalid.0))?;
        if choices.contains_key(&host) {
            return Err(ForgeError::InvalidInput(format!("Two credentials are chosen for {host}: choose one.")));
        }
        let key = uuid_of(choice.ssh_key_id.as_deref(), "SSH key")?;
        let token = uuid_of(choice.https_token_id.as_deref(), "HTTPS token")?;
        if key.is_some() && token.is_some() {
            return Err(ForgeError::InvalidInput(format!(
                "The repositories of {host} are cloned with an SSH key or an HTTPS token, not both."
            )));
        }
        if let Some(key) = key
            && !keys.contains_key(&key)
        {
            return Err(ForgeError::InvalidInput(format!("No SSH key with id {key}.")));
        }
        if let Some(token) = token {
            let bound = tokens.get(&host).is_some_and(|bound| bound.iter().any(|(id, _)| *id == token));
            if !bound {
                let exists = tokens.values().flatten().any(|(id, _)| *id == token);
                return Err(ForgeError::InvalidInput(if exists {
                    format!(
                        "This HTTPS token is issued for another host and would be sent to no other: the repositories \
                         of {host} need a token bound to {host}."
                    )
                } else {
                    format!("No HTTPS token with id {token}.")
                }));
            }
        }
        choices.insert(host, Choice { ssh_key_id: key, https_token_id: token, proposed: false });
    }
    Ok(choices)
}

/// The one HTTPS token bound to the host when there is exactly one; none otherwise.
fn proposal(host: &str, tokens: &HashMap<String, Vec<(Uuid, String)>>) -> Choice {
    match tokens.get(host).map(Vec::as_slice) {
        Some([(id, _)]) => Choice { ssh_key_id: None, https_token_id: Some(*id), proposed: true },
        _ => Choice { ssh_key_id: None, https_token_id: None, proposed: true },
    }
}

fn credential_view(
    choice: &Choice,
    keys: &HashMap<Uuid, String>,
    tokens: &HashMap<String, Vec<(Uuid, String)>>,
) -> CredentialView {
    if let Some(key) = choice.ssh_key_id {
        return CredentialView { kind: "ssh_key", id: Some(key.to_string()), name: keys.get(&key).cloned() };
    }
    if let Some(token) = choice.https_token_id {
        let name = tokens.values().flatten().find(|(id, _)| *id == token).map(|(_, name)| name.clone());
        return CredentialView { kind: "https_token", id: Some(token.to_string()), name };
    }
    CredentialView { kind: "none", id: None, name: None }
}

/// The identities of the forge's two clone URLs.
fn identities_of(row: &RepositoryRow) -> Vec<String> {
    let mut identities = Vec::with_capacity(2);
    if let Some(identity) = row.http_url.as_deref().and_then(repository_url::identity) {
        identities.push(identity);
    }
    if let Some(identity) = row.ssh_url.as_deref().and_then(repository_url::identity)
        && !identities.contains(&identity)
    {
        identities.push(identity);
    }
    identities
}

fn normalized(host: &str) -> String {
    java::to_lower_root(host).trim_end_matches('.').to_owned()
}

/// The host a connection's repositories are cloned from: its web address's.
fn connection_host(connection: &ConnectionRow) -> String {
    repository_url::host(&connection.base_url).map(|host| normalized(&host)).unwrap_or_default()
}

/// Why a clone URL may not be imported from this connection: its host is not the connection's.
fn elsewhere(url: &str, forge_host: &str) -> Option<String> {
    let host = repository_url::host(url).map(|host| normalized(&host));
    if host.as_deref().is_some_and(|host| !forge_host.is_empty() && host == forge_host) {
        return None;
    }
    Some(format!(
        "The forge gives a clone URL on {}, not on {forge_host}, this connection's host: an import clones only from \
         the forge it was discovered on. Add the repository by hand if that host is meant.",
        host.map_or_else(
            || "a host that cannot be read".to_owned(),
            |found| bounded_text::clip(Some(&found), 100).unwrap_or_default().to_owned()
        )
    ))
}

/// The host the repository is cloned from: its HTTPS clone URL's, or its SSH URL's.
fn host_of(repository: &RepositoryRow) -> String {
    repository
        .http_url
        .as_deref()
        .and_then(repository_url::host)
        .or_else(|| repository.ssh_url.as_deref().and_then(repository_url::host))
        .map(|host| normalized(&host))
        .unwrap_or_default()
}

/// A private repository imported with no credential fails its first scan, visibly: said first.
fn warning(repository: &RepositoryRow, choice: &Choice) -> Option<String> {
    if choice.ssh_key_id.is_some() || choice.https_token_id.is_some() {
        return None;
    }
    if repository.visibility.as_deref().is_some_and(|visibility| visibility.eq_ignore_ascii_case("public")) {
        return None;
    }
    Some(format!(
        "{} and is imported with no clone credential: its scans will fail with \"requires authentication\" unless it \
         can be cloned anonymously.",
        repository.visibility.as_deref().map_or_else(
            || "The forge did not say whether this repository is public".to_owned(),
            |visibility| format!("This repository is {visibility}")
        )
    ))
}

fn uuid_of(value: Option<&str>, what: &str) -> Result<Option<Uuid>, ForgeError> {
    let Some(value) = value.filter(|value| !java::is_blank(value)) else {
        return Ok(None);
    };
    let trimmed = java::trim(value);
    super::path::java_uuid(trimmed).and_then(|canonical| Uuid::parse_str(&canonical).ok()).map(Some).ok_or_else(|| {
        ForgeError::InvalidInput(format!(
            "\"{}\" is not a valid {what} identifier.",
            bounded_text::clip(Some(trimmed), 60).unwrap_or_default()
        ))
    })
}

/// Whether two readings of one request create the same.
pub(crate) fn same_creations(first: &Plan, second: &Plan) -> bool {
    first.creations() == second.creations()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_are_grouped_as_java_writes_them() {
        assert_eq!(grouped(1_000), "1,000");
        assert_eq!(grouped(20_001), "20,001");
        assert_eq!(grouped(999), "999");
    }

    #[test]
    fn the_spacing_is_bounded_and_off_by_default() {
        assert_eq!(spacing(None, None).unwrap(), None);
        assert_eq!(spacing(Some(true), None).unwrap(), Some(60));
        assert!(spacing(Some(true), Some(9)).is_err());
        assert!(spacing(Some(false), Some(601)).is_err());
    }

    #[test]
    fn forge_ids_are_distinct_trimmed_and_refused_when_empty() {
        let ids = forge_ids(Some(&[Some(" 1 ".into()), Some("1".into()), Some("2".into())]), 10, "x").unwrap();
        assert_eq!(ids, vec!["1", "2"]);
        assert!(forge_ids(Some(&[None]), 10, "x").is_err());
        assert_eq!(
            forge_ids(Some(&[Some("1".into()), Some("2".into())]), 1, "An import").unwrap_err().to_string(),
            "An import takes at most 1 repositories; this one names 2. Import a larger selection in several parts."
        );
    }
}
