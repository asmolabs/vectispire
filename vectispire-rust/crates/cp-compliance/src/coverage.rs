//! The OWASP Top 10:2021 grid's measurement — Java's `OwaspCoverageService` and `OwaspScopes`: what the deployment
//! reads (the switches, the categories its rules declare, each target's newest finished scan), the open counts the
//! grid is assessed from, and a target's own split for the weekly record. The assessment is
//! `vectispire_domain::owasp_coverage`'s.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use serde::Serialize;
use vectispire_cp_access::Allowance;
use vectispire_cp_access::rows::ScopeKind;
use vectispire_cp_db::{ScanTarget, Visibility};
use vectispire_cp_issues::queries::{IssueCatalog, IssueFilters};
use vectispire_cp_rules::RuleCoverageService;
use vectispire_cp_rules::coverage::State as RuleState;
use vectispire_cp_scanning::ScanCatalog;
use vectispire_cp_settings::{Setting, Settings};
use vectispire_cp_targets::Targets;
use vectispire_domain::FindingType;
use vectispire_domain::ScanTarget as DomainTarget;
use vectispire_domain::language::Language;
use vectispire_domain::observation::Observation;
use vectispire_domain::owasp_coverage::{self, Evidence, Grid, Measurement, Split};
use vectispire_domain::scan_status::ScanStatus;

use crate::error::ComplianceError;

/// `Reading`: what the deployment reads, once per pass.
#[derive(Debug, Clone)]
pub struct Reading {
    pub end_of_life_enabled: bool,
    pub code_analysis_enabled: bool,
    pub declared_by_rules: BTreeSet<String>,
    pub evidence: BTreeMap<ScanTarget, Evidence>,
}

impl Reading {
    fn of(&self, target: ScanTarget) -> Evidence {
        self.evidence.get(&target).cloned().unwrap_or_else(|| Evidence::never_scanned(domain_target(target)))
    }

    /// `codeAnalysisReachesItsRepositories`: code analysis on, and every repository whose newest scan ran it and
    /// recorded its languages read at least one — **read per repository and per language**, as the grid reads it,
    /// and none read is not "reaches".
    pub fn code_analysis_reaches_its_repositories(&self) -> bool {
        if !self.code_analysis_enabled {
            return false;
        }
        let read: Vec<&Evidence> = self
            .evidence
            .values()
            .filter(|one| matches!(one.target, DomainTarget::Repository(_)))
            .filter(|one| one.examined().is_some_and(|types| types.contains(&FindingType::Sast)))
            .filter(|one| one.analysed().is_some())
            .collect();
        !read.is_empty() && read.iter().all(|one| one.analysed().is_some_and(|languages| !languages.is_empty()))
    }
}

/// `OwaspWeeklyScope`: the project or solution a grid or a week was narrowed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatedScope {
    pub kind: &'static str,
    pub id: i64,
    pub name: String,
    pub partial: bool,
    pub target_count: i32,
}

/// `OwaspScopes.Scoped`: the visibility a scope narrows to, and the scope as stated.
#[derive(Debug, Clone)]
pub struct Scoped {
    pub visibility: Visibility,
    pub stated: Option<StatedScope>,
}

/// `ScopedGrid`.
#[derive(Debug, Clone)]
pub struct ScopedGrid {
    pub grid: Grid,
    pub scope: Option<StatedScope>,
    pub unplaced_code: i64,
}

#[derive(Clone)]
pub struct OwaspCoverageService {
    issues: Arc<IssueCatalog>,
    scans: Arc<ScanCatalog>,
    targets: Arc<Targets>,
    rules: Arc<RuleCoverageService>,
    settings: Settings,
}

impl std::fmt::Debug for OwaspCoverageService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("OwaspCoverageService").finish_non_exhaustive()
    }
}

/// `OwaspScopes.atMostOne`.
pub fn at_most_one(project_id: Option<i64>, solution_id: Option<i64>) -> Result<(), ComplianceError> {
    if project_id.is_some() && solution_id.is_some() {
        return Err(ComplianceError::Invalid("Name a project or a solution, not both.".to_owned()));
    }
    Ok(())
}

impl OwaspCoverageService {
    pub fn new(
        issues: Arc<IssueCatalog>,
        scans: Arc<ScanCatalog>,
        targets: Arc<Targets>,
        rules: Arc<RuleCoverageService>,
        settings: Settings,
    ) -> OwaspCoverageService {
        OwaspCoverageService { issues, scans, targets, rules, settings }
    }

    /// `OwaspScopes.resolve`: at most one scope, then the project's or the solution's visible targets — refused as
    /// absent when the caller sees none of it — or the caller's own view.
    pub async fn resolve(
        &self,
        project_id: Option<i64>,
        solution_id: Option<i64>,
        allowance: &Allowance,
    ) -> Result<Scoped, ComplianceError> {
        at_most_one(project_id, solution_id)?;
        let scope = match (project_id, solution_id) {
            (Some(id), _) => Some(self.targets.visible_project(id, allowance).await.map_err(refusal)?),
            (None, Some(id)) => Some(self.targets.visible_solution(id, allowance).await.map_err(refusal)?),
            (None, None) => None,
        };
        Ok(match scope {
            None => Scoped { visibility: allowance.visibility.clone(), stated: None },
            Some(scope) => Scoped {
                visibility: Visibility::Only(scope.visible.iter().copied().collect()),
                stated: Some(StatedScope {
                    kind: match scope.kind {
                        ScopeKind::Project => "project",
                        ScopeKind::Solution => "solution",
                    },
                    id: scope.id,
                    target_count: i32::try_from(scope.visible.len()).unwrap_or(i32::MAX),
                    name: scope.name,
                    partial: scope.partial,
                }),
            },
        })
    }

    /// `reading()`. **What the installed rules declare, not what the findings carry**: categories derived from the
    /// findings would leave the grid the day the last finding is fixed.
    pub async fn reading(&self) -> Result<Reading, ComplianceError> {
        let end_of_life_enabled =
            self.settings.is_enabled(Setting::EolEnabled).await.map_err(ComplianceError::unexpected)?;
        // Java's `&&`: the rules are assessed only when code analysis is switched on.
        let code_analysis_enabled =
            self.settings.is_enabled(Setting::SastEnabled).await.map_err(ComplianceError::unexpected)?
                && self.rules.assess().await.map_err(ComplianceError::unexpected)?.state != RuleState::Unconfigured;
        let declared_by_rules = self.rules.declared_owasp_categories().await.map_err(ComplianceError::unexpected)?;
        let mut by_language: HashMap<Language, BTreeSet<String>> = HashMap::new();
        for (directory, categories) in
            self.rules.declared_owasp_categories_by_language().await.map_err(ComplianceError::unexpected)?
        {
            if let Some(language) = Language::from_wire_name(&directory) {
                by_language.entry(language).or_default().extend(categories);
            }
        }
        Ok(Reading {
            end_of_life_enabled,
            code_analysis_enabled,
            declared_by_rules,
            evidence: self.evidence(&by_language).await?,
        })
    }

    /// Each existing target's evidence from its newest finished scan; a target never scanned has its own.
    async fn evidence(
        &self,
        by_language: &HashMap<Language, BTreeSet<String>>,
    ) -> Result<BTreeMap<ScanTarget, Evidence>, ComplianceError> {
        let mut newest = BTreeMap::new();
        for row in self.scans.latest_finished_per_repository().await.map_err(ComplianceError::unexpected)? {
            newest.insert(ScanTarget::Repository(row.target_id), row);
        }
        for row in self.scans.latest_finished_per_container().await.map_err(ComplianceError::unexpected)? {
            newest.insert(ScanTarget::Container(row.target_id), row);
        }
        let scan_ids: Vec<i64> = newest.values().map(|row| row.scan_id).collect();
        let outlines = self.scans.outlines_of(&scan_ids).await.map_err(ComplianceError::unexpected)?;
        let languages = self.scans.languages_of(&scan_ids).await.map_err(ComplianceError::unexpected)?;

        let mut evidence = BTreeMap::new();
        for target in self.existing_targets().await? {
            let Some(row) = newest.get(&target) else {
                evidence.insert(target, Evidence::never_scanned(domain_target(target)));
                continue;
            };
            // A status this version does not know reads as no observation, as the gate reads it.
            let observation = Observation::of(ScanStatus::from_wire_name(Some(&row.status)));
            let examined = outlines
                .get(&row.scan_id)
                .and_then(|outline| outline.examined_types.as_ref())
                .map(|types| types.iter().copied().collect::<BTreeSet<_>>());
            let recorded = languages.get(&row.scan_id);
            let detected = recorded.and_then(|one| one.detected.clone());
            let sast_rules = recorded.and_then(|one| one.sast_rules.clone());
            evidence.insert(
                target,
                Evidence::of(
                    domain_target(target),
                    observation,
                    examined,
                    detected.as_ref(),
                    sast_rules.as_ref(),
                    by_language,
                ),
            );
        }
        Ok(evidence)
    }

    /// Every repository then every image, in the catalogue's order.
    pub async fn existing_targets(&self) -> Result<Vec<ScanTarget>, ComplianceError> {
        let repositories = self.targets.catalog_repositories().await.map_err(ComplianceError::unexpected)?;
        let containers = self.targets.catalog_containers().await.map_err(ComplianceError::unexpected)?;
        Ok(repositories
            .iter()
            .map(|row| ScanTarget::Repository(row.id))
            .chain(containers.iter().map(|row| ScanTarget::Container(row.id)))
            .collect())
    }

    /// `grid(projectId, solutionId, allowance)`: the scope resolved, then the grid and the unplaced code over it.
    pub async fn scoped(
        &self,
        project_id: Option<i64>,
        solution_id: Option<i64>,
        allowance: &Allowance,
    ) -> Result<ScopedGrid, ComplianceError> {
        let scoped = self.resolve(project_id, solution_id, allowance).await?;
        Ok(ScopedGrid {
            grid: self.grid(&scoped.visibility).await?,
            unplaced_code: self.unplaced_code(&scoped.visibility).await?,
            scope: scoped.stated,
        })
    }

    /// `grid(allowed)`. **Asked of the reader's estate, not of the deployment**: a restricted reader whose targets
    /// were never scanned is told their categories are unmeasured, whatever the rest of the estate shows.
    pub async fn grid(&self, allowed: &Visibility) -> Result<Grid, ComplianceError> {
        let reading = self.reading().await?;
        let in_scope: Vec<Evidence> = reading
            .evidence
            .iter()
            .filter(|(target, _)| allowed.permits(**target))
            .map(|(_, one)| one.clone())
            .collect();
        Ok(owasp_coverage::assess(&self.measurement(allowed, &reading, true, in_scope).await?))
    }

    /// `ofTarget`: one target's grid, its unsettled findings and its settled ones apart.
    pub async fn of_target(&self, target: ScanTarget, reading: &Reading) -> Result<Vec<Split>, ComplianceError> {
        let only = Visibility::Only(BTreeSet::from([target]));
        let evidence = vec![reading.of(target)];
        let one =
            |measurement: Measurement| owasp_coverage::assess_target(&measurement).map_err(ComplianceError::unexpected);
        let unsettled = one(self.measurement(&only, reading, true, evidence.clone()).await?)?;
        let all = one(self.measurement(&only, reading, false, evidence).await?)?;
        Ok(owasp_coverage::split(&unsettled, &all))
    }

    /// `unplacedCode`: the open code findings no category holds.
    async fn unplaced_code(&self, allowed: &Visibility) -> Result<i64, ComplianceError> {
        let open_code = self.count_open(owasp_coverage::DECLARES_ITS_CATEGORY, allowed, true).await?;
        let by_category = self.open_by_category(allowed, true).await?;
        Ok(owasp_coverage::unplaced_code(open_code, by_category.iter().map(|(code, count)| (code.as_str(), *count))))
    }

    async fn measurement(
        &self,
        allowed: &Visibility,
        reading: &Reading,
        exclude_settled: bool,
        targets: Vec<Evidence>,
    ) -> Result<Measurement, ComplianceError> {
        let mut open_by_type = HashMap::new();
        for type_ in FindingType::ALL {
            if owasp_coverage::category_of(type_).is_some() {
                open_by_type.insert(type_, self.count_open(type_, allowed, exclude_settled).await?);
            }
        }
        Ok(Measurement {
            end_of_life_enabled: reading.end_of_life_enabled,
            code_analysis_enabled: reading.code_analysis_enabled,
            open_by_type,
            declared_by_rules: reading.declared_by_rules.clone(),
            open_by_category: self.open_by_category(allowed, exclude_settled).await?,
            targets,
        })
    }

    async fn open_by_category(
        &self,
        allowed: &Visibility,
        exclude_settled: bool,
    ) -> Result<HashMap<String, i64>, ComplianceError> {
        let mut filters = IssueFilters::new(allowed.clone());
        filters.exclude_settled = exclude_settled;
        let mut by_category: HashMap<String, i64> = HashMap::new();
        for row in self.issues.count_open_sast_by_owasp_category(&filters).await.map_err(ComplianceError::unexpected)? {
            let sum = by_category.entry(row.owasp_category).or_default();
            *sum = sum.saturating_add(row.c);
        }
        Ok(by_category)
    }

    async fn count_open(
        &self,
        type_: FindingType,
        allowed: &Visibility,
        exclude_settled: bool,
    ) -> Result<i64, ComplianceError> {
        let mut filters = IssueFilters::new(allowed.clone());
        filters.type_ = Some(type_.wire_name().to_owned());
        filters.exclude_settled = exclude_settled;
        self.issues.count(&filters).await.map_err(ComplianceError::unexpected)
    }
}

/// The domain's spelling of a target: the grid is decided there, without the database's types.
fn domain_target(target: ScanTarget) -> DomainTarget {
    match target {
        ScanTarget::Repository(id) => DomainTarget::Repository(id),
        ScanTarget::Container(id) => DomainTarget::Container(id),
    }
}

/// The scope's refusal as it is — a 404 carrying the guard's sentence — and anything else unexpected.
fn refusal(error: vectispire_cp_targets::TargetError) -> ComplianceError {
    match error {
        vectispire_cp_targets::TargetError::NotFound(message) => ComplianceError::NotFound(message),
        other => ComplianceError::unexpected(other),
    }
}
