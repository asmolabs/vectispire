//! The compliance matrix — Java's `ComplianceService`: the estate's (or one target's) evaluation per framework, the
//! MTTR, and one row per visible target.
//!
//! **Read in separate transactions** where Java holds one read-only transaction: the overview, the counts and the rows
//! are each a snapshot of their own. A scan finishing between two of them can make the matrix and the totals disagree
//! by that scan, as posture's dashboard already may; nothing here is written.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::decisions::{self, ComplianceEvaluation, ComplianceFramework, PlatformPosture, PostureInput};
use serde::Serialize;
use serde_json::{Map, Value};
use time::{Duration, OffsetDateTime};
use vectispire_cp_db::{ScanTarget, Visibility};
use vectispire_cp_gate::GateService;
use vectispire_cp_gate::overview::{Overview, TargetPosture};
use vectispire_cp_issues::SlaService;
use vectispire_cp_issues::queries::{IssueCatalog, IssueFilters, TargetBreakdown};
use vectispire_cp_settings::{Setting, Settings};
use vectispire_cp_targets::Clock;
use vectispire_domain::instant::Instant;
use vectispire_domain::mttr::{self, MttrResult, ResolvedIssue};
use vectispire_domain::observation::Observation;
use vectispire_domain::triage_status::TriageStatus;
use vectispire_domain::{FindingType, Severity};

use crate::error::ComplianceError;
use crate::ports::{Inventories, Platform};

/// The refusal of a `targetId` naming no kind, or no number — Java's sentence.
pub const MALFORMED_TARGET: &str = "A target is written repository:<id> or container:<id>.";

/// One target's row of the matrix — `TargetCompliance`, members in the record's order. `frameworkScores` in the
/// evaluations' order (the frameworks' declaration order), a framework with no data left out.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetCompliance {
    pub target_id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub type_: &'static str,
    pub gate_status: &'static str,
    pub open_issues_count: i64,
    pub overdue_count: i64,
    pub overall_score: i32,
    pub overall_status: &'static str,
    pub framework_scores: Map<String, Value>,
}

/// `ComplianceSummary`. `observed_targets` and `fresh_targets` are what the verdicts were capped by: without them a
/// score cannot tell a clean estate from an unobserved one.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceSummary {
    pub evaluations: Vec<ComplianceEvaluation>,
    pub mttr: MttrResult,
    pub overdue_count: i64,
    /// Always zero, as Java's: nothing computes it.
    pub due_soon_count: i64,
    pub total_monitored_targets: i32,
    pub passing_gate_targets: i32,
    pub observed_targets: i32,
    pub fresh_targets: i32,
    pub targets: Vec<TargetCompliance>,
}

/// `TargetCounts`: one target's open, unsettled issues on every axis the summary reports. **"sast" counts the
/// `quality` type**, as Java's summary always has — kept, not corrected, in a port.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TargetCounts {
    critical: i64,
    high: i64,
    medium: i64,
    low: i64,
    kev: i64,
    secrets: i64,
    sast: i64,
    iac: i64,
}

impl TargetCounts {
    fn plus(self, row: &TargetBreakdown) -> TargetCounts {
        let n = row.c;
        let when = |yes: bool| if yes { n } else { 0 };
        let severity = Severity::of(row.severity.as_deref());
        TargetCounts {
            critical: self.critical.saturating_add(when(severity == Severity::Critical)),
            high: self.high.saturating_add(when(severity == Severity::High)),
            medium: self.medium.saturating_add(when(severity == Severity::Medium)),
            low: self.low.saturating_add(when(severity == Severity::Low)),
            kev: self.kev.saturating_add(when(row.is_kev)),
            secrets: self.secrets.saturating_add(when(row.type_ == FindingType::Secret.wire_name())),
            sast: self.sast.saturating_add(when(row.type_ == FindingType::Quality.wire_name())),
            iac: self.iac.saturating_add(when(row.type_ == FindingType::Iac.wire_name())),
        }
    }

    fn total(self) -> i64 {
        self.critical.saturating_add(self.high).saturating_add(self.medium).saturating_add(self.low)
    }
}

/// How the matrix keys a target: `repo:<id>` or `container:<id>`.
fn target_key(target: ScanTarget) -> String {
    match target {
        ScanTarget::Repository(id) => format!("repo:{id}"),
        ScanTarget::Container(id) => format!("container:{id}"),
    }
}

/// `TargetScores.of`: the measured frameworks' scores and their rounded average; none measured is `NO_DATA` at zero.
fn target_scores(evaluations: &[ComplianceEvaluation]) -> (Map<String, Value>, i32, &'static str) {
    let mut scores = Map::new();
    let mut sum: i64 = 0;
    let mut measured: i64 = 0;
    for evaluation in evaluations.iter().filter(|evaluation| evaluation.overall_status.measured()) {
        scores.insert(evaluation.framework.name().to_owned(), Value::from(evaluation.score_percentage));
        sum = sum.saturating_add(i64::from(evaluation.score_percentage));
        measured = measured.saturating_add(1);
    }
    if measured == 0 {
        return (scores, 0, "NO_DATA");
    }
    // `Math.round` of the `double` average: half up.
    #[allow(clippy::cast_precision_loss)]
    let average = vectispire_domain::java_math::round(sum as f64 / measured as f64);
    let average = i32::try_from(average).unwrap_or(i32::MAX);
    let status = if average == 100 {
        "COMPLIANT"
    } else if average >= 70 {
        "PARTIAL"
    } else {
        "NON_COMPLIANT"
    };
    (scores, average, status)
}

/// The gate's word for one target's row.
fn gate_status(posture: &TargetPosture) -> &'static str {
    match posture.observation {
        Observation::InProgress => "SCANNING",
        Observation::NeverScanned => "NEVER_SCANNED",
        Observation::LastScanFailed => "FAILED",
        _ if posture.passed => "PASSED",
        _ => "FAILED",
    }
}

/// `namedTarget`: the target a request's `targetId` names, or `None` for the estate — absent, blank, `ALL`, or the
/// `null` / `undefined` a client's template writes for nothing, case aside.
pub fn named_target(target_id: Option<&str>) -> Option<&str> {
    let target_id = target_id?;
    let asks_for_the_estate = vectispire_domain::java::is_blank(target_id)
        || ["ALL", "null", "undefined"].iter().any(|word| target_id.eq_ignore_ascii_case(word));
    (!asks_for_the_estate).then_some(target_id)
}

/// `targetNumber`: the number after the first colon, trimmed — refused in words, never the parser's.
fn target_number(target_id: &str) -> Result<i64, ComplianceError> {
    let after = target_id.find(':').map_or(target_id, |colon| target_id.get(colon.saturating_add(1)..).unwrap_or(""));
    vectispire_domain::java::read_long(vectispire_domain::java::trim(after))
        .ok_or_else(|| ComplianceError::Invalid(MALFORMED_TARGET.to_owned()))
}

/// `getSummaryForTarget`'s parse: `repo:` or `repository:`, or `container:`.
fn parse_target(target_id: &str) -> Result<ScanTarget, ComplianceError> {
    if target_id.starts_with("repo:") || target_id.starts_with("repository:") {
        Ok(ScanTarget::Repository(target_number(target_id)?))
    } else if target_id.starts_with("container:") {
        Ok(ScanTarget::Container(target_number(target_id)?))
    } else {
        Err(ComplianceError::Invalid(MALFORMED_TARGET.to_owned()))
    }
}

/// What one summary reads once and every row reuses.
struct Shared {
    platform: PlatformPosture,
    audit_valid: bool,
    counts: BTreeMap<String, TargetCounts>,
    overdue_by_target: BTreeMap<String, i64>,
    window_days: i32,
    fresh_within: i32,
    with_inventory: BTreeSet<ScanTarget>,
}

#[derive(Clone)]
pub struct ComplianceService {
    gate: Arc<GateService>,
    issues: Arc<IssueCatalog>,
    sla: Arc<SlaService>,
    settings: Settings,
    platform: Arc<dyn Platform>,
    inventories: Arc<dyn Inventories>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ComplianceService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ComplianceService").finish_non_exhaustive()
    }
}

impl ComplianceService {
    pub fn new(
        gate: Arc<GateService>,
        issues: Arc<IssueCatalog>,
        sla: Arc<SlaService>,
        settings: Settings,
        platform: Arc<dyn Platform>,
        inventories: Arc<dyn Inventories>,
        clock: Arc<dyn Clock>,
    ) -> ComplianceService {
        ComplianceService { gate, issues, sla, settings, platform, inventories, clock }
    }

    /// The estate's summary, as the reader sees it.
    pub async fn summary(&self, allowed: &Visibility) -> Result<ComplianceSummary, ComplianceError> {
        self.summary_of(None, allowed).await
    }

    /// `getSummary(targetId, allowed)`. **A hidden or absent target is not refused**, and the matrix is not narrowed
    /// to it — Java's 1.0 answers 200 with `NO_DATA` and one monitored target; kept, as a port keeps a contract.
    pub async fn summary_of(
        &self,
        target_id: Option<&str>,
        allowed: &Visibility,
    ) -> Result<ComplianceSummary, ComplianceError> {
        let named = named_target(target_id).map(parse_target).transpose()?;
        let posture = self.gate.overview(allowed).await.map_err(ComplianceError::unexpected)?;
        let shared = self.shared(&posture, allowed).await?;
        match named {
            None => self.estate(&posture, &shared, allowed).await,
            Some(target) => self.one_target(target, &posture, &shared, allowed).await,
        }
    }

    /// `getEvaluation`: the estate summary's evaluation of this framework. Java's fallback is unreachable — every
    /// framework is evaluated — and is not ported.
    pub async fn evaluation(
        &self,
        framework: ComplianceFramework,
        allowed: &Visibility,
    ) -> Result<ComplianceEvaluation, ComplianceError> {
        let summary = self.summary(allowed).await?;
        summary
            .evaluations
            .into_iter()
            .find(|evaluation| evaluation.framework == framework)
            .ok_or_else(|| ComplianceError::unexpected(format!("no evaluation of {}", framework.name())))
    }

    async fn shared(&self, posture: &Overview, allowed: &Visibility) -> Result<Shared, ComplianceError> {
        let audit_valid = self.platform.audit_chain_valid().await.map_err(ComplianceError::Unexpected)?;
        let platform = self.platform.posture().await.map_err(ComplianceError::Unexpected)?;
        let mut counts: BTreeMap<String, TargetCounts> = BTreeMap::new();
        // Settled triage left out, as the estate's counts below already do.
        let rows = self
            .issues
            .count_open_grouped_by_target("open", TriageStatus::settled_wire_names())
            .await
            .map_err(ComplianceError::unexpected)?;
        for row in &rows {
            let target = match (row.repo_id, row.container_id) {
                (Some(id), _) => ScanTarget::Repository(id),
                (None, Some(id)) => ScanTarget::Container(id),
                (None, None) => continue,
            };
            let entry = counts.entry(target_key(target)).or_default();
            *entry = entry.plus(row);
        }
        let overdue_by_target = self.sla.count_overdue_by_target(allowed).await.map_err(ComplianceError::unexpected)?;
        let setting =
            self.settings.as_int(Setting::ComplianceFreshnessDays).await.map_err(ComplianceError::unexpected)?;
        let window_days = setting.max(0);
        let fresh_within = if window_days == 0 {
            posture.total_count
        } else {
            let fresh = posture.targets.iter().filter(|target| self.fresh(target, window_days)).count();
            i32::try_from(fresh).unwrap_or(i32::MAX)
        };
        let with_inventory = self.inventories.targets_with_inventory().await.map_err(ComplianceError::Unexpected)?;
        Ok(Shared { platform, audit_valid, counts, overdue_by_target, window_days, fresh_within, with_inventory })
    }

    /// One target counts as fresh on its own terms — on nothing when the window is off. Its latest scan, whatever its
    /// status, at or after the cutoff.
    fn fresh(&self, target: &TargetPosture, window_days: i32) -> bool {
        if window_days == 0 {
            return true;
        }
        let cutoff = self.clock.now().checked_sub(Duration::days(i64::from(window_days)));
        match (target.last_scan.as_ref(), cutoff) {
            (Some(scan), Some(cutoff)) => scan.created_at >= cutoff,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    async fn count(&self, filters: IssueFilters) -> Result<i64, ComplianceError> {
        self.issues.count(&filters).await.map_err(ComplianceError::unexpected)
    }

    /// `countOpen` / `countOpenType`: open, settled triage left out, narrowed to a target when one is named.
    fn open(allowed: &Visibility, target: Option<ScanTarget>) -> IssueFilters {
        let mut filters = IssueFilters::new(allowed.clone());
        filters.exclude_settled = true;
        match target {
            Some(ScanTarget::Repository(id)) => filters.repo_id = Some(id),
            Some(ScanTarget::Container(id)) => filters.container_id = Some(id),
            None => {}
        }
        filters
    }

    /// The nine counts an evaluation reads, for the estate or one target; `overdue` handed in, since the estate's and
    /// a target's are read differently.
    async fn input_counts(
        &self,
        allowed: &Visibility,
        target: Option<ScanTarget>,
    ) -> Result<[i64; 8], ComplianceError> {
        let severity = |severity: Severity| {
            let mut filters = Self::open(allowed, target);
            filters.severity = Some(severity.wire_name().to_owned());
            filters
        };
        let of_type = |type_: FindingType| {
            let mut filters = Self::open(allowed, target);
            filters.type_ = Some(type_.wire_name().to_owned());
            filters
        };
        let mut kev = Self::open(allowed, target);
        kev.only_kev = true;
        Ok([
            self.count(severity(Severity::Critical)).await?,
            self.count(severity(Severity::High)).await?,
            self.count(severity(Severity::Medium)).await?,
            self.count(severity(Severity::Low)).await?,
            self.count(kev).await?,
            self.count(of_type(FindingType::Secret)).await?,
            // `quality`, as the per-target counts.
            self.count(of_type(FindingType::Quality)).await?,
            self.count(of_type(FindingType::Iac)).await?,
        ])
    }

    /// The MTTR over the reader's resolved issues, a target's when one is named.
    async fn mttr(&self, allowed: &Visibility, target: Option<ScanTarget>) -> Result<MttrResult, ComplianceError> {
        let mut filters = IssueFilters::new(allowed.clone());
        filters.state = Some("resolved".to_owned());
        match target {
            Some(ScanTarget::Repository(id)) => filters.repo_id = Some(id),
            Some(ScanTarget::Container(id)) => filters.container_id = Some(id),
            None => {}
        }
        let rows = self.issues.resolutions(&filters).await.map_err(ComplianceError::unexpected)?;
        let resolved: Vec<ResolvedIssue> = rows
            .iter()
            .map(|row| ResolvedIssue {
                severity: Some(Severity::of(row.severity.as_deref())),
                first_seen_at: Some(instant(row.first_seen_at)),
                resolved_at: row.resolved_at.map(instant),
            })
            .collect();
        Ok(mttr::calculate(&resolved))
    }

    /// One row per target of the posture, from the grouped reads taken once.
    fn rows(&self, posture: &Overview, shared: &Shared) -> Vec<TargetCompliance> {
        posture
            .targets
            .iter()
            .map(|target| {
                let key = target_key(target.target);
                let counts = shared.counts.get(&key).copied().unwrap_or_default();
                let overdue = shared.overdue_by_target.get(&key).copied().unwrap_or(0);
                let passed = target.observed && target.passed;
                let input = PostureInput {
                    total_targets: 1,
                    scanned_targets: i32::from(target.observed),
                    freshly_scanned_targets: i32::from(self.fresh(target, shared.window_days)),
                    freshness_window_days: shared.window_days,
                    gate_passing_targets: i32::from(passed),
                    critical_issues: counts.critical,
                    high_issues: counts.high,
                    medium_issues: counts.medium,
                    low_issues: counts.low,
                    kev_issues: counts.kev,
                    overdue_issues: overdue,
                    secret_issues: counts.secrets,
                    sast_issues: counts.sast,
                    iac_issues: counts.iac,
                    targets_with_sbom: i32::from(shared.with_inventory.contains(&target.target)),
                    audit_chain_valid: shared.audit_valid,
                };
                let (scores, average, status) = target_scores(&decisions::evaluate_all(&input, &shared.platform));
                TargetCompliance {
                    target_id: key,
                    name: target.name.clone(),
                    type_: match target.target {
                        ScanTarget::Repository(_) => "REPOSITORY",
                        ScanTarget::Container(_) => "CONTAINER",
                    },
                    gate_status: gate_status(target),
                    open_issues_count: counts.total(),
                    overdue_count: overdue,
                    overall_score: average,
                    overall_status: status,
                    framework_scores: scores,
                }
            })
            .collect()
    }

    async fn estate(
        &self,
        posture: &Overview,
        shared: &Shared,
        allowed: &Visibility,
    ) -> Result<ComplianceSummary, ComplianceError> {
        let observed = count(posture.targets.iter().filter(|target| target.observed));
        let passing = count(posture.targets.iter().filter(|target| target.observed && target.passed));
        let [critical, high, medium, low, kev, secrets, sast, iac] = self.input_counts(allowed, None).await?;
        let overdue = self.sla.count_overdue(allowed).await.map_err(ComplianceError::unexpected)?;
        let with_sbom = count(posture.targets.iter().filter(|target| shared.with_inventory.contains(&target.target)));
        // The count as it is, zero included: the engine divides by at least one itself.
        let input = PostureInput {
            total_targets: posture.total_count,
            scanned_targets: observed,
            freshly_scanned_targets: shared.fresh_within,
            freshness_window_days: shared.window_days,
            gate_passing_targets: passing,
            critical_issues: critical,
            high_issues: high,
            medium_issues: medium,
            low_issues: low,
            kev_issues: kev,
            overdue_issues: overdue,
            secret_issues: secrets,
            sast_issues: sast,
            iac_issues: iac,
            targets_with_sbom: with_sbom,
            audit_chain_valid: shared.audit_valid,
        };
        Ok(ComplianceSummary {
            evaluations: decisions::evaluate_all(&input, &shared.platform),
            mttr: self.mttr(allowed, None).await?,
            overdue_count: overdue,
            due_soon_count: 0,
            total_monitored_targets: posture.total_count,
            passing_gate_targets: passing,
            observed_targets: observed,
            fresh_targets: shared.fresh_within,
            targets: self.rows(posture, shared),
        })
    }

    async fn one_target(
        &self,
        target: ScanTarget,
        posture: &Overview,
        shared: &Shared,
        allowed: &Visibility,
    ) -> Result<ComplianceSummary, ComplianceError> {
        let found = posture.targets.iter().find(|candidate| candidate.target == target);
        let observed = found.is_some_and(|found| found.observed);
        let passing = i32::from(found.is_some_and(|found| found.observed && found.passed));
        let [critical, high, medium, low, kev, secrets, sast, iac] = self.input_counts(allowed, Some(target)).await?;
        // `countOverdueForTarget`: the thresholds as a filter, none configured reading zero.
        let thresholds = self.sla.overdue_thresholds(self.clock.now()).await.map_err(ComplianceError::unexpected)?;
        let overdue = if thresholds.is_empty() {
            0
        } else {
            let mut filters = Self::open(allowed, Some(target));
            filters.overdue_before = thresholds;
            self.count(filters).await?
        };
        let input = PostureInput {
            total_targets: 1,
            scanned_targets: i32::from(observed),
            freshly_scanned_targets: shared.fresh_within,
            freshness_window_days: shared.window_days,
            gate_passing_targets: passing,
            critical_issues: critical,
            high_issues: high,
            medium_issues: medium,
            low_issues: low,
            kev_issues: kev,
            overdue_issues: overdue,
            secret_issues: secrets,
            sast_issues: sast,
            iac_issues: iac,
            targets_with_sbom: i32::from(shared.with_inventory.contains(&target)),
            audit_chain_valid: shared.audit_valid,
        };
        Ok(ComplianceSummary {
            evaluations: decisions::evaluate_all(&input, &shared.platform),
            mttr: self.mttr(allowed, Some(target)).await?,
            overdue_count: overdue,
            due_soon_count: 0,
            total_monitored_targets: 1,
            passing_gate_targets: passing,
            observed_targets: i32::from(observed),
            fresh_targets: shared.fresh_within,
            targets: self.rows(posture, shared),
        })
    }
}

fn count<T>(items: impl Iterator<Item = T>) -> i32 {
    i32::try_from(items.count()).unwrap_or(i32::MAX)
}

fn instant(at: OffsetDateTime) -> Instant {
    Instant { epoch_second: at.unix_timestamp(), nano: at.nanosecond() }
}
