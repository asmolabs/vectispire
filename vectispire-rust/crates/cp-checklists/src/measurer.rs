//! `ChecklistMeasurer`: what a line's rule finds on a project now — the owners asked what they recorded, through
//! their own catalogues, and [`crate::evaluation::evaluate`] applying the rule (decision 0032 §6).
//!
//! **Each owner answers its own question**, through a port this module declares: the scans, the backlog, the
//! inventory and the repositories' schedules ([`ScanEvidence`], which the binary implements over `cp-scanning`,
//! `cp-issues`, `cp-inventory` and `cp-targets`); the imports and the plugins' manifests ([`ImportEvidence`]); the
//! forges' readings ([`ReviewEvidence`]). No other module's table is read here.
//!
//! **The plugins and forges modules are not ported yet** (waves 2 and 3): their ports are answered by [`NoImports`]
//! and [`NoReviews`], which know of no import and no reading — every repository "never examined" by them, which a
//! rule reads as no data, never as a pass (decision 0007).
//!
//! Nothing here opens a transaction or writes: a measurement is stored by whoever relies on it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use vectispire_domain::checklists::facts::{
    Component, CoverageReport, Imported, IssueCount, Look, MeasurementFacts, PackageCounts, Packages, PluginRun,
    PluginRuns, PluginState, ReviewFacts, ScanLanguages, Scanned, ScopeFacts, Source, TestReport,
};
use vectispire_domain::finding_type::FindingType;
use vectispire_domain::instant::Instant;
use vectispire_domain::language::Language;

use crate::error::ChecklistError;
use crate::evaluation;
use crate::measurement::Measurement;
use crate::persistence::ItemRow;
use crate::rule::ChecklistRule;
use crate::tool_scope::ToolScope;

/// A port's answer: the value, or why the owner could not give it — a failure, never an empty answer (decision 0007).
pub type Answer<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;

/// `ExaminingScanRow`: the newest scan in which a built-in step produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExaminingScan {
    pub scan_id: i64,
    pub created_at: Instant,
    pub sbom_stored: bool,
}

/// `ScanCatalog.ScansWithin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScansWithin {
    pub completed: i64,
    pub unrecorded: i64,
}

/// `ScanCatalog.PluginRun`: a plugin's stored state in one scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginRunRow {
    pub scan_id: i64,
    pub created_at: Instant,
    pub state: String,
    pub refusal: Option<String>,
    pub manifest_digest: Option<String>,
}

/// `IssueCatalog.ScopeCount`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeCount {
    pub repository_id: i64,
    pub severity: String,
    pub state: String,
    pub count: i64,
}

/// What the scans, the backlog, the inventory and the repositories' schedules answer.
pub trait ScanEvidence: Send + Sync {
    /// `ScanCatalog.newestExamining`, at any age.
    fn newest_examining<'a>(
        &'a self,
        repositories: &'a [i64],
        step: FindingType,
    ) -> Answer<'a, BTreeMap<i64, ExaminingScan>>;
    /// `ScanCatalog.completedWithin`.
    fn completed_within<'a>(
        &'a self,
        repositories: &'a [i64],
        since: Instant,
    ) -> Answer<'a, BTreeMap<i64, ScansWithin>>;
    /// `ScanCatalog.pluginRunsWithin`.
    fn plugin_runs_within<'a>(
        &'a self,
        repositories: &'a [i64],
        plugin_id: &'a str,
        since: Instant,
    ) -> Answer<'a, BTreeMap<i64, Vec<PluginRunRow>>>;
    /// `ScanCatalog.namingPluginBefore`.
    fn naming_plugin_before<'a>(
        &'a self,
        repositories: &'a [i64],
        plugin_id: &'a str,
        since: Instant,
    ) -> Answer<'a, BTreeSet<i64>>;
    /// `ScanCatalog.languagesOf`.
    fn languages_of<'a>(&'a self, scan_ids: &'a [i64]) -> Answer<'a, BTreeMap<i64, ScanLanguages>>;
    /// `IssueCatalog.countUnsettledOfTypeWithin`.
    fn count_unsettled_of_type<'a>(&'a self, step: FindingType, repositories: &'a [i64])
    -> Answer<'a, Vec<ScopeCount>>;
    /// `IssueCatalog.countUnsettledOfToolWithin`.
    fn count_unsettled_of_tool<'a>(&'a self, tool_key: &'a str, repositories: &'a [i64])
    -> Answer<'a, Vec<ScopeCount>>;
    /// `ComponentCatalog.componentsOf`, by scan.
    fn components_of<'a>(&'a self, scan_ids: &'a [i64]) -> Answer<'a, BTreeMap<i64, Vec<Component>>>;
    /// `Schedules.runsAtLeastEvery` for each repository, the schedule in force as the scheduler reads it.
    fn scheduled<'a>(
        &'a self,
        repositories: &'a [i64],
        max_age_days: i32,
        now: Instant,
    ) -> Answer<'a, BTreeMap<i64, bool>>;
}

/// A coverage import as the plugins' catalogue answers it (`CoverageImportView`).
#[derive(Debug, Clone)]
pub struct CoverageImport {
    pub look: Look,
    pub lines_covered: i64,
    pub lines_total: i64,
    pub branches_covered: Option<i64>,
    pub branches_total: Option<i64>,
    /// `packages_state`: `None` before the record existed (V71).
    pub packages_state: Option<String>,
    /// `CoveragePackages.State.why`, for a state other than `kept`, as its evidence prints it.
    pub not_kept_because: Option<String>,
}

/// What the plugins' imports and manifests answer (`ReportImportCatalog`, `PluginService.manifest`).
pub trait ImportEvidence: Send + Sync {
    /// `newestCarrying`: the newest SARIF import carrying the tool, as a look.
    fn newest_carrying<'a>(&'a self, repositories: &'a [i64], scope_key: &'a str) -> Answer<'a, BTreeMap<i64, Look>>;
    /// `unrecordedSince`.
    fn unrecorded_since<'a>(
        &'a self,
        repositories: &'a [i64],
        source_slug: &'a str,
        since: Instant,
    ) -> Answer<'a, BTreeSet<i64>>;
    /// `newestCoverage`.
    fn newest_coverage<'a>(&'a self, repositories: &'a [i64]) -> Answer<'a, BTreeMap<i64, CoverageImport>>;
    /// `coveragePackages`.
    fn coverage_packages<'a>(&'a self, import_id: i64) -> Answer<'a, Vec<PackageCounts>>;
    /// `newestTestReports`.
    fn newest_test_reports<'a>(&'a self, repositories: &'a [i64]) -> Answer<'a, BTreeMap<i64, TestReport>>;
    /// `PluginService.manifest(...).languages()`: `None` when that manifest is not known.
    fn manifest_languages<'a>(&'a self, plugin_id: &'a str, digest: &'a str) -> Answer<'a, Option<BTreeSet<Language>>>;
}

/// `ChangeReviews`: what the forges recorded of how changes reach each repository's branch.
pub trait ReviewEvidence: Send + Sync {
    fn recorded<'a>(
        &'a self,
        repositories: &'a [i64],
        branch: Option<&'a str>,
    ) -> Answer<'a, BTreeMap<i64, ReviewFacts>>;
}

/// The plugins module's stand-in until wave 2: no import and no manifest known.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoImports;

impl ImportEvidence for NoImports {
    fn newest_carrying<'a>(&'a self, _: &'a [i64], _: &'a str) -> Answer<'a, BTreeMap<i64, Look>> {
        Box::pin(async { Ok(BTreeMap::new()) })
    }
    fn unrecorded_since<'a>(&'a self, _: &'a [i64], _: &'a str, _: Instant) -> Answer<'a, BTreeSet<i64>> {
        Box::pin(async { Ok(BTreeSet::new()) })
    }
    fn newest_coverage<'a>(&'a self, _: &'a [i64]) -> Answer<'a, BTreeMap<i64, CoverageImport>> {
        Box::pin(async { Ok(BTreeMap::new()) })
    }
    fn coverage_packages<'a>(&'a self, _: i64) -> Answer<'a, Vec<PackageCounts>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn newest_test_reports<'a>(&'a self, _: &'a [i64]) -> Answer<'a, BTreeMap<i64, TestReport>> {
        Box::pin(async { Ok(BTreeMap::new()) })
    }
    fn manifest_languages<'a>(&'a self, _: &'a str, _: &'a str) -> Answer<'a, Option<BTreeSet<Language>>> {
        Box::pin(async { Ok(None) })
    }
}

/// The forges module's stand-in until wave 3: no repository was ever read.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoReviews;

impl ReviewEvidence for NoReviews {
    fn recorded<'a>(&'a self, _: &'a [i64], _: Option<&'a str>) -> Answer<'a, BTreeMap<i64, ReviewFacts>> {
        Box::pin(async { Ok(BTreeMap::new()) })
    }
}

/// What one bound line's rule found.
#[derive(Debug, Clone)]
pub struct LineMeasurement {
    pub(crate) item: ItemRow,
    pub(crate) rule: ChecklistRule,
    pub(crate) measurement: Measurement,
}

/// The measurer.
#[derive(Clone)]
pub struct Measurer {
    scans: Arc<dyn ScanEvidence>,
    imports: Arc<dyn ImportEvidence>,
    reviews: Arc<dyn ReviewEvidence>,
}

impl std::fmt::Debug for Measurer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Measurer").finish_non_exhaustive()
    }
}

fn failed(why: String) -> ChecklistError {
    ChecklistError::Failed(why)
}

impl Measurer {
    pub fn new(
        scans: Arc<dyn ScanEvidence>,
        imports: Arc<dyn ImportEvidence>,
        reviews: Arc<dyn ReviewEvidence>,
    ) -> Measurer {
        Measurer { scans, imports, reviews }
    }

    /// Every bound line of `items`, measured over these repositories at `now`, in their order.
    pub(crate) async fn measure_all(
        &self,
        repository_ids: &[i64],
        items: &[ItemRow],
        now: Instant,
    ) -> Result<Vec<LineMeasurement>, ChecklistError> {
        let mut measured = Vec::new();
        for item in items.iter().filter(|item| item.bound_rule.is_some()) {
            measured.push(self.measure(repository_ids, item, now).await?);
        }
        Ok(measured)
    }

    pub(crate) async fn measure(
        &self,
        repository_ids: &[i64],
        item: &ItemRow,
        now: Instant,
    ) -> Result<LineMeasurement, ChecklistError> {
        let canonical = item.bound_rule.as_deref().unwrap_or("null");
        let rule = ChecklistRule::from_canonical(canonical)?;
        let facts = self.facts(&rule, repository_ids, now).await?;
        let measurement = evaluation::evaluate(&rule, &facts, now)?;
        Ok(LineMeasurement { item: item.clone(), rule, measurement })
    }

    // ------------------------------------------------------------------ asking the owners

    async fn facts(
        &self,
        rule: &ChecklistRule,
        repository_ids: &[i64],
        now: Instant,
    ) -> Result<MeasurementFacts, ChecklistError> {
        let repositories: Vec<i64> = repository_ids.iter().copied().collect::<BTreeSet<_>>().into_iter().collect();
        let mut facts = MeasurementFacts { repository_ids: repositories.clone(), ..MeasurementFacts::default() };
        if repositories.is_empty() {
            return Ok(facts);
        }
        let since = now
            .minus_days(i64::from(rule.max_age_days()))
            .ok_or_else(|| ChecklistError::defect("A rule's age reaches before the epoch's range."))?;
        let mut language_scans: BTreeSet<i64> = BTreeSet::new();
        match rule {
            ChecklistRule::DependencyAnalysis { require_schedule, .. } => {
                let scope = ToolScope::BuiltIn(FindingType::Vulnerability).key();
                facts
                    .scopes
                    .insert(scope.clone(), self.scanned(&repositories, FindingType::Vulnerability, since).await?.0);
                facts.counts.insert(
                    scope,
                    counts(
                        self.scans
                            .count_unsettled_of_type(FindingType::Vulnerability, &repositories)
                            .await
                            .map_err(failed)?,
                    ),
                );
                if *require_schedule {
                    facts.scheduled =
                        self.scans.scheduled(&repositories, rule.max_age_days(), now).await.map_err(failed)?;
                }
            }
            ChecklistRule::FindingsThreshold { scopes, .. } => {
                for scope in scopes {
                    let key = scope.key();
                    match scope {
                        ToolScope::BuiltIn(step) => {
                            let (scanned, newest) = self.scanned(&repositories, *step, since).await?;
                            facts.scopes.insert(key.clone(), scanned);
                            if matches!(step, FindingType::Sast | FindingType::Quality) {
                                language_scans.extend(newest.values().map(|row| row.scan_id));
                            }
                            facts.counts.insert(
                                key,
                                counts(self.scans.count_unsettled_of_type(*step, &repositories).await.map_err(failed)?),
                            );
                        }
                        ToolScope::Plugin(plugin_id) => {
                            let runs = self.plugin(&repositories, plugin_id, since).await?;
                            for facts in runs.values() {
                                if let ScopeFacts::PluginRuns(runs) = facts {
                                    language_scans.extend(runs.within_age.iter().map(|run| run.scan.id));
                                }
                            }
                            facts.scopes.insert(key.clone(), runs);
                            facts.counts.insert(
                                key.clone(),
                                counts(self.scans.count_unsettled_of_tool(&key, &repositories).await.map_err(failed)?),
                            );
                        }
                        ToolScope::Imported { source_slug, .. } => {
                            let imported = self.imported(&repositories, &key, source_slug, since).await?;
                            facts.scopes.insert(key.clone(), imported);
                            facts.counts.insert(
                                key.clone(),
                                counts(self.scans.count_unsettled_of_tool(&key, &repositories).await.map_err(failed)?),
                            );
                        }
                    }
                }
            }
            ChecklistRule::CoverageThreshold { scope, .. } => {
                facts.coverage = self.coverage(&repositories, scope.is_some()).await?;
            }
            ChecklistRule::TestSuitePassed { .. } => {
                facts.tests = self.imports.newest_test_reports(&repositories).await.map_err(failed)?;
            }
            // Both read the same inventory, the newest scan whose dependency step produced: a presence line and a
            // versions line on one project never answer from two different SBOMs.
            ChecklistRule::ComponentVersions { .. } | ChecklistRule::ComponentPresent { .. } => {
                let scope = ToolScope::BuiltIn(FindingType::Vulnerability).key();
                let (scanned, newest) = self.scanned(&repositories, FindingType::Vulnerability, since).await?;
                facts.scopes.insert(scope, scanned);
                facts.components = self.components(&newest).await?;
            }
            // Stored by the forges' hourly reading: nothing here calls a forge.
            ChecklistRule::ChangeReview { branch, .. } => {
                facts.reviews = self.reviews.recorded(&repositories, branch.as_deref()).await.map_err(failed)?;
            }
        }
        if !language_scans.is_empty() {
            let ids: Vec<i64> = language_scans.into_iter().collect();
            facts.languages = self.scans.languages_of(&ids).await.map_err(failed)?;
        }
        Ok(facts)
    }

    /// A built-in step's facts per repository, and the newest scans in which it produced, at any age.
    async fn scanned(
        &self,
        repositories: &[i64],
        step: FindingType,
        since: Instant,
    ) -> Result<(BTreeMap<i64, ScopeFacts>, BTreeMap<i64, ExaminingScan>), ChecklistError> {
        // At any age: whether the newest look is within the age, stale or absent is the rule's to say.
        let newest = self.scans.newest_examining(repositories, step).await.map_err(failed)?;
        let within = self.scans.completed_within(repositories, since).await.map_err(failed)?;
        let mut facts = BTreeMap::new();
        for repository in repositories {
            let row = newest.get(repository);
            let counted = within.get(repository).copied().unwrap_or_default();
            let recorded = counted.completed.saturating_sub(counted.unrecorded);
            facts.insert(
                *repository,
                ScopeFacts::Scanned(Scanned {
                    newest_producing: row.map(|scan| Look {
                        source: Source::Scan,
                        id: scan.scan_id,
                        at: scan.created_at,
                        digest: None,
                    }),
                    sbom_stored: row.is_some_and(|scan| scan.sbom_stored),
                    recorded_within_age: i32::try_from(recorded).unwrap_or(i32::MAX),
                    unrecorded_within_age: i32::try_from(counted.unrecorded).unwrap_or(i32::MAX),
                }),
            );
        }
        Ok((facts, newest))
    }

    async fn plugin(
        &self,
        repositories: &[i64],
        plugin_id: &str,
        since: Instant,
    ) -> Result<BTreeMap<i64, ScopeFacts>, ChecklistError> {
        let runs = self.scans.plugin_runs_within(repositories, plugin_id, since).await.map_err(failed)?;
        let within = self.scans.completed_within(repositories, since).await.map_err(failed)?;
        let named_before = self.scans.naming_plugin_before(repositories, plugin_id, since).await.map_err(failed)?;
        // By the digest each scan named, never the plugin's current manifest: an update that added a language would
        // otherwise claim it for scans that ran without it.
        let mut declared: HashMap<String, Option<BTreeSet<Language>>> = HashMap::new();
        let mut facts = BTreeMap::new();
        for repository in repositories {
            let mut states = Vec::new();
            for run in runs.get(repository).map_or(&[][..], Vec::as_slice) {
                let reads = match run.manifest_digest.as_deref() {
                    None => None,
                    Some(digest) => match declared.get(digest) {
                        Some(known) => known.clone(),
                        None => {
                            let languages = self.imports.manifest_languages(plugin_id, digest).await.map_err(failed)?;
                            declared.insert(digest.to_owned(), languages.clone());
                            languages
                        }
                    },
                };
                states.push(PluginRun {
                    scan: Look { source: Source::Scan, id: run.scan_id, at: run.created_at, digest: None },
                    state: state(&run.state, run.refusal.as_deref()),
                    reads,
                });
            }
            let completed = within.get(repository).map_or(0, |counted| counted.completed);
            facts.insert(
                *repository,
                ScopeFacts::PluginRuns(PluginRuns {
                    within_age: states,
                    scans_within_age: i32::try_from(completed).unwrap_or(i32::MAX),
                    named_before: named_before.contains(repository),
                }),
            );
        }
        Ok(facts)
    }

    async fn imported(
        &self,
        repositories: &[i64],
        key: &str,
        source_slug: &str,
        since: Instant,
    ) -> Result<BTreeMap<i64, ScopeFacts>, ChecklistError> {
        let newest = self.imports.newest_carrying(repositories, key).await.map_err(failed)?;
        let unrecorded = self.imports.unrecorded_since(repositories, source_slug, since).await.map_err(failed)?;
        Ok(repositories
            .iter()
            .map(|repository| {
                (
                    *repository,
                    ScopeFacts::Imported(Imported {
                        newest_producing: newest.get(repository).cloned(),
                        unrecorded_within_age: unrecorded.contains(repository),
                    }),
                )
            })
            .collect())
    }

    /// The newest coverage import of each repository — and, for a scoped rule, what it kept of its packages.
    async fn coverage(
        &self,
        repositories: &[i64],
        scoped: bool,
    ) -> Result<BTreeMap<i64, CoverageReport>, ChecklistError> {
        let mut reports = BTreeMap::new();
        for (repository, row) in self.imports.newest_coverage(repositories).await.map_err(failed)? {
            let packages = if !scoped {
                Packages::NotRead
            } else {
                match row.packages_state.as_deref() {
                    None => Packages::Unrecorded,
                    Some("kept") => Packages::Kept(self.imports.coverage_packages(row.look.id).await.map_err(failed)?),
                    Some(other) => Packages::NotKept(row.not_kept_because.clone().unwrap_or_else(|| {
                        format!("the import's packages are in a state this version does not know ({other})")
                    })),
                }
            };
            reports.insert(
                repository,
                CoverageReport {
                    look: row.look,
                    lines_covered: row.lines_covered,
                    lines_total: row.lines_total,
                    branches_covered: row.branches_covered,
                    branches_total: row.branches_total,
                    packages,
                },
            );
        }
        Ok(reports)
    }

    /// The components of each repository's newest analysed scan; an empty list where the inventory holds none.
    async fn components(
        &self,
        newest: &BTreeMap<i64, ExaminingScan>,
    ) -> Result<BTreeMap<i64, Vec<Component>>, ChecklistError> {
        let scan_ids: Vec<i64> = newest.values().map(|scan| scan.scan_id).collect();
        let by_scan = self.scans.components_of(&scan_ids).await.map_err(failed)?;
        Ok(newest
            .iter()
            .map(|(repository, scan)| (*repository, by_scan.get(&scan.scan_id).cloned().unwrap_or_default()))
            .collect())
    }
}

/// A plugin's stored state, decision 0017's three and the refusal by its reason. One this version does not know did
/// not produce: read as absent — should have run, did not — never as produced nor as not applicable.
fn state(stored: &str, refusal: Option<&str>) -> PluginState {
    match stored {
        "produced" => PluginState::Produced,
        "not_applicable" => PluginState::NotApplicable,
        "refused" => match refusal {
            Some("unsigned") => PluginState::RefusedUnsigned,
            Some("signature_unverified") => PluginState::RefusedSignatureUnverified,
            Some("registry_authentication_required") => PluginState::RefusedRegistryAuthenticationRequired,
            _ => PluginState::Absent,
        },
        _ => PluginState::Absent,
    }
}

fn counts(rows: Vec<ScopeCount>) -> BTreeMap<i64, Vec<IssueCount>> {
    let mut by_repository: BTreeMap<i64, Vec<IssueCount>> = BTreeMap::new();
    for row in rows {
        by_repository.entry(row.repository_id).or_default().push(IssueCount {
            severity: row.severity,
            state: row.state,
            count: row.count,
        });
    }
    by_repository
}
