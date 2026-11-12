//! `RuleEvaluation`: a rule applied to what the owners recorded about a project (decision 0032 §6) — pure: the facts
//! and the instant in, a [`Measurement`] out.
//!
//! **No data is never a pass** (decision 0007 applied to a line): a project without a repository, a step absent in
//! every scan within the age, a scan from before `examined_types`, a plugin not applicable anywhere — each has no
//! data, and one repository without data makes the line's measurement `no_data`. **Thresholds are judged on complete
//! data only**: with a repository missing, the figures are reported, unjudged.
//!
//! The counts arrive with settled triage already left out by the owner's own query, so a triage status this version
//! does not know is counted; an issue's state is read the same way — only `resolved` is resolved.

use std::collections::{BTreeMap, BTreeSet};

use vectispire_domain::checklists::facts::{
    Component, CoverageReport, IssueCount, MeasurementFacts, Packages, PluginRun, PluginState, ReviewFacts,
    ScanLanguages, ScopeFacts,
};
use vectispire_domain::checklists::review::MergedChange;
use vectispire_domain::checklists::{Look, Source};
use vectispire_domain::instant::Instant;
use vectispire_domain::java;
use vectispire_domain::language::Language;
use vectispire_domain::{FindingType, Severity};

use crate::Defect;
use crate::allowed_component::{self as component, AllowedComponent};
use crate::decimal::Ratio;
use crate::measurement::{
    ALL_SCOPES, EXAMINED, Figure, Measurement, MeasurementOutcome, NOT_APPLICABLE, NoDataReason, RepositoryEvidence,
};
use crate::rule::{Aggregation, ChecklistRule, Metric, Thresholds};
use crate::source_languages;
use crate::suite_pattern::SuitePattern;
use crate::tool_scope::ToolScope;

/// What one scope was on one repository, once the rules have read its facts.
#[derive(Debug, Clone)]
enum ScopeState {
    /// `note`: what the evidence adds to "examined" — which languages were read, for one.
    Examined {
        look: Look,
        note: Option<String>,
    },
    NotApplicable(Look),
    Missing {
        reason: NoDataReason,
        newest: Option<Look>,
        detail: Option<String>,
    },
}

fn missing(reason: NoDataReason, newest: Option<Look>) -> ScopeState {
    ScopeState::Missing { reason, newest, detail: None }
}

fn examined(look: Look) -> ScopeState {
    ScopeState::Examined { look, note: None }
}

/// The rule over the facts, as of `now`. A defect only for facts the caller should not have handed over — a scoped
/// coverage rule given a report whose packages were not read.
pub fn evaluate(rule: &ChecklistRule, facts: &MeasurementFacts, now: Instant) -> Result<Measurement, Defect> {
    let repositories: Vec<i64> = facts.repository_ids.iter().copied().collect::<BTreeSet<i64>>().into_iter().collect();
    if repositories.is_empty() {
        return Measurement::new(
            MeasurementOutcome::NoData,
            Some(NoDataReason::NoRepository),
            None,
            Vec::new(),
            Vec::new(),
            "No data: the project has no repository, and a line is not passed by none of them.".to_owned(),
        );
    }
    let since = now
        .minus_days(i64::from(rule.max_age_days()))
        .ok_or_else(|| Defect("The maximum age reaches before the time line.".to_owned()))?;
    match rule {
        ChecklistRule::DependencyAnalysis { max_age_days, require_schedule, thresholds } => {
            dependencies(*max_age_days, *require_schedule, thresholds, facts, &repositories, since)
        }
        ChecklistRule::FindingsThreshold { scopes, thresholds, .. } => {
            findings(scopes, thresholds, facts, &repositories, since)
        }
        ChecklistRule::CoverageThreshold { metric, minimum_ratio, aggregation, scope, .. } => coverage(
            &Coverage {
                metric: *metric,
                minimum_ratio: *minimum_ratio,
                aggregation: *aggregation,
                scope: scope.as_ref(),
            },
            facts,
            &repositories,
            since,
        ),
        ChecklistRule::TestSuitePassed { suite_patterns, minimum_tests, .. } => {
            tests(suite_patterns, *minimum_tests, facts, &repositories, since)
        }
        ChecklistRule::ComponentVersions { components, .. } => {
            components_versions(components, facts, &repositories, since)
        }
        ChecklistRule::ComponentPresent { purl_prefixes, .. } => present(purl_prefixes, facts, &repositories, since),
        ChecklistRule::ChangeReview { minimum_approvals, window_days, minimum_ratio, branch, .. } => change_review(
            &Review {
                minimum_approvals: *minimum_approvals,
                window_days: *window_days,
                minimum_ratio: *minimum_ratio,
                branch: branch.as_deref(),
            },
            facts,
            &repositories,
            since,
        ),
    }
}

// ------------------------------------------------------------------ one scope on one repository

/// What the facts about one scope say of one repository. The order of the questions is the rule: a step that
/// produced within the age is examined, whatever else happened; a scan within the age that recorded its steps
/// without this one says it did not look; one from before the record says nothing; with nothing within the age, an
/// older look is stale, and no look at all is never.
fn classify(facts: Option<&ScopeFacts>, since: Instant) -> ScopeState {
    match facts {
        None => missing(NoDataReason::NeverExamined, None),
        Some(ScopeFacts::Scanned(scanned)) => {
            let newest = scanned.newest_producing.clone();
            if let Some(look) = newest.as_ref().filter(|look| look.at >= since) {
                return examined(look.clone());
            }
            if scanned.recorded_within_age > 0 {
                return missing(NoDataReason::StepAbsent, newest);
            }
            if scanned.unrecorded_within_age > 0 {
                return missing(NoDataReason::ExaminationUnrecorded, newest);
            }
            let reason = if newest.is_some() { NoDataReason::Stale } else { NoDataReason::NeverExamined };
            missing(reason, newest)
        }
        Some(ScopeFacts::PluginRuns(runs)) => {
            let mut within: Vec<&PluginRun> = runs.within_age.iter().filter(|run| run.scan.at >= since).collect();
            within.sort_by_key(|run| std::cmp::Reverse(run.scan.at));
            if let Some(produced) = within.iter().find(|run| run.state == PluginState::Produced) {
                return examined(produced.scan.clone());
            }
            // Absent or refused once within the age and never produced: it should have run and did not, which
            // outweighs a "not applicable" beside it. The newest of them names the reason.
            if let Some(failed) = within.iter().find(|run| run.state != PluginState::NotApplicable) {
                let scan = Some(failed.scan.clone());
                let (reason, detail) = match failed.state {
                    PluginState::RefusedUnsigned => (
                        NoDataReason::PluginUnsigned,
                        Some(
                            "the executor refused the plugin: its manifest declares no signer, a signer is required, \
                              and no waiver covers it",
                        ),
                    ),
                    PluginState::RefusedSignatureUnverified => (
                        NoDataReason::PluginSignatureUnverified,
                        Some(
                            "the executor refused the plugin: the signer its manifest declares did not verify its image",
                        ),
                    ),
                    PluginState::RefusedRegistryAuthenticationRequired => (
                        NoDataReason::PluginRegistryAuthenticationRequired,
                        Some(
                            "the executor refused the plugin: the registry of its image would not let the signature \
                              be read (authentication required)",
                        ),
                    ),
                    _ => (NoDataReason::StepAbsent, None),
                };
                return ScopeState::Missing { reason, newest: scan, detail: detail.map(str::to_owned) };
            }
            if let Some(first) = within.first() {
                return ScopeState::NotApplicable(first.scan.clone());
            }
            // Scans within the age that do not name it ran without it: a plugin missing from a scan is absent.
            if runs.scans_within_age > 0 {
                return missing(NoDataReason::StepAbsent, None);
            }
            missing(if runs.named_before { NoDataReason::Stale } else { NoDataReason::NeverExamined }, None)
        }
        Some(ScopeFacts::Imported(imported)) => {
            let newest = imported.newest_producing.clone();
            if let Some(look) = newest.as_ref().filter(|look| look.at >= since) {
                return examined(look.clone());
            }
            if imported.unrecorded_within_age {
                return missing(NoDataReason::ExaminationUnrecorded, newest);
            }
            let reason = if newest.is_some() { NoDataReason::Stale } else { NoDataReason::NeverExamined };
            missing(reason, newest)
        }
    }
}

// ------------------------------------------------------------------ what the analysis read

/// An examined scope, asked whether its analysis read the tree it produced on — for the built-in SAST and quality
/// steps (Semgrep and its rules) and every plugin, **judged on the scan the measurement rests on**, by what that scan
/// recorded. A step that produced on a tree it could not read found nothing because it read nothing.
fn read(
    scope: &ToolScope,
    scoped: Option<&ScopeFacts>,
    state: ScopeState,
    languages: &BTreeMap<i64, ScanLanguages>,
) -> ScopeState {
    let ScopeState::Examined { look, .. } = &state else { return state };
    let recorded = if look.source == Source::Scan { languages.get(&look.id) } else { None };
    match scope {
        ToolScope::BuiltIn(FindingType::Sast | FindingType::Quality) => semgrep(look, recorded),
        ToolScope::Plugin(_) => plugin(look, scoped, recorded),
        _ => state,
    }
}

fn semgrep(look: &Look, recorded: Option<&ScanLanguages>) -> ScopeState {
    let Some(detected) = recorded.and_then(|recorded| recorded.detected.as_ref()) else {
        return ScopeState::Missing {
            reason: NoDataReason::LanguagesUnrecorded,
            newest: Some(look.clone()),
            detail: Some(format!(
                "scan {} recorded no census of its tree: which languages it holds, and so whether its rules read any \
                 of them, is unknown",
                look.id
            )),
        };
    };
    let Some(rules) = recorded.and_then(|recorded| recorded.sast_rules.as_ref()) else {
        return ScopeState::Missing {
            reason: NoDataReason::LanguagesUnrecorded,
            newest: Some(look.clone()),
            detail: Some(format!("scan {} did not record which languages its SAST rules read", look.id)),
        };
    };
    let source = source_languages::of(detected);
    let read = format!("its SAST rules read {}", names(rules));
    if source.is_empty() {
        return ScopeState::Missing {
            reason: NoDataReason::LanguageNotAnalysed,
            newest: Some(look.clone()),
            detail: Some(format!(
                "its tree holds no source language the census recognises (found: {}); {read} — nothing says its code \
                 was analysed",
                names(detected)
            )),
        };
    }
    let unread: BTreeSet<Language> = source.iter().copied().filter(|language| !rules.contains(language)).collect();
    if !unread.is_empty() {
        return ScopeState::Missing {
            reason: NoDataReason::LanguageNotAnalysed,
            newest: Some(look.clone()),
            detail: Some(format!(
                "not analysed: {} — source languages in its tree: {}; {read}",
                names(&unread),
                names(&source)
            )),
        };
    }
    ScopeState::Examined { look: look.clone(), note: Some(format!("source languages analysed: {}", names(&source))) }
}

fn plugin(look: &Look, scoped: Option<&ScopeFacts>, recorded: Option<&ScanLanguages>) -> ScopeState {
    let Some(detected) = recorded.and_then(|recorded| recorded.detected.as_ref()) else {
        // An incomplete census runs every plugin: produced on a tree nobody counted, it may have read none of it.
        return ScopeState::Missing {
            reason: NoDataReason::LanguagesUnrecorded,
            newest: Some(look.clone()),
            detail: Some(format!(
                "scan {} recorded no census of its tree: a plugin runs on such a tree whatever its languages, and may \
                 have read nothing",
                look.id
            )),
        };
    };
    let declared = match scoped {
        Some(ScopeFacts::PluginRuns(runs)) => {
            runs.within_age.iter().find(|run| run.scan == *look).and_then(|run| run.reads.as_ref())
        }
        _ => None,
    };
    let Some(reads) = declared else {
        return ScopeState::Missing {
            reason: NoDataReason::LanguagesUnrecorded,
            newest: Some(look.clone()),
            detail: Some(format!(
                "the manifest scan {} ran the plugin with is no longer known: which languages it reads is unknown",
                look.id
            )),
        };
    };
    if !detected.iter().any(|language| reads.contains(language)) {
        return ScopeState::Missing {
            reason: NoDataReason::LanguageNotAnalysed,
            newest: Some(look.clone()),
            detail: Some(format!(
                "it reads {}, and its tree holds none of them (found: {})",
                names(reads),
                names(detected)
            )),
        };
    }
    let unread: BTreeSet<Language> =
        source_languages::of(detected).into_iter().filter(|language| !reads.contains(language)).collect();
    let note = if unread.is_empty() {
        format!("it reads {}", names(reads))
    } else {
        format!("it reads {}; source languages in its tree it does not read: {}", names(reads), names(&unread))
    };
    ScopeState::Examined { look: look.clone(), note: Some(note) }
}

fn names(languages: &BTreeSet<Language>) -> String {
    if languages.is_empty() {
        return "none".to_owned();
    }
    let mut names: Vec<&str> = languages.iter().map(|language| language.wire_name()).collect();
    names.sort_unstable();
    names.join(", ")
}

// ------------------------------------------------------------------ the kinds

/// Open and resolved, per severity in the enum's order.
type Counts = BTreeMap<Severity, (i64, i64)>;

fn findings(
    scopes: &[ToolScope],
    thresholds: &Thresholds,
    facts: &MeasurementFacts,
    repositories: &[i64],
    since: Instant,
) -> Result<Measurement, Defect> {
    let mut collector = Collector::default();
    let mut totals: Counts = BTreeMap::new();
    let mut figures = Vec::new();
    for scope in scopes {
        let key = scope.key();
        let included = collector.scope(scope, facts, repositories, since);
        for (severity, (open, resolved)) in counts(facts.counts.get(&key), &included) {
            figures.push(Figure {
                scope: key.clone(),
                severity: severity.wire_name().to_owned(),
                open,
                resolved,
                met: None,
                detail: None,
            });
            let total = totals.entry(severity).or_insert((0, 0));
            total.0 = total.0.saturating_add(open);
            total.1 = total.1.saturating_add(resolved);
        }
    }
    let what = scopes.iter().map(ToolScope::key).collect::<Vec<_>>().join(", ");
    judged(collector, thresholds, &totals, figures, &what)
}

const VULNERABILITY: &str = "builtin:vulnerability";

fn dependencies(
    max_age_days: i32,
    require_schedule: bool,
    thresholds: &Thresholds,
    facts: &MeasurementFacts,
    repositories: &[i64],
    since: Instant,
) -> Result<Measurement, Defect> {
    let mut collector = Collector::default();
    let scoped = facts.scopes.get(VULNERABILITY);
    for &repository in repositories {
        let about = scoped.and_then(|scoped| scoped.get(&repository));
        let state = classify(about, since);
        let ScopeState::Examined { look, .. } = state else {
            collector.add(repository, None, state);
            continue;
        };
        let mut unmet = Vec::new();
        if !matches!(about, Some(ScopeFacts::Scanned(scanned)) if scanned.sbom_stored) {
            unmet.push("its newest analysed scan stored no SBOM".to_owned());
        }
        if require_schedule && !facts.scheduled.get(&repository).copied().unwrap_or(false) {
            unmet.push(format!("it is not scheduled at least every {}", days(max_age_days)));
        }
        collector.examined(repository, None, look, unmet, None);
    }
    let included = collector.included.clone();
    let totals = counts(facts.counts.get(VULNERABILITY), &included);
    let figures = totals
        .iter()
        .map(|(severity, (open, resolved))| Figure {
            scope: VULNERABILITY.to_owned(),
            severity: severity.wire_name().to_owned(),
            open: *open,
            resolved: *resolved,
            met: None,
            detail: None,
        })
        .collect();
    judged(collector, thresholds, &totals, figures, "dependency analysis")
}

struct Coverage<'a> {
    metric: Metric,
    minimum_ratio: Ratio,
    aggregation: Aggregation,
    scope: Option<&'a crate::coverage_scope::CoverageScope>,
}

fn coverage(
    rule: &Coverage<'_>,
    facts: &MeasurementFacts,
    repositories: &[i64],
    since: Instant,
) -> Result<Measurement, Defect> {
    let mut collector = Collector::default();
    let mut covered_sum = 0i64;
    let mut total_sum = 0i64;
    for &repository in repositories {
        let Some(report) = facts.coverage.get(&repository) else {
            collector.add(repository, None, missing(NoDataReason::NeverExamined, None));
            continue;
        };
        if report.look.at < since {
            collector.add(repository, None, missing(NoDataReason::Stale, Some(report.look.clone())));
            continue;
        }
        if rule.metric == Metric::Branch && (report.branches_total.is_none() || report.branches_covered.is_none()) {
            // Counted no branch: not 0 of 0, and not a pass — it did not look.
            collector.missing(
                repository,
                None,
                NoDataReason::StepAbsent,
                Some(report.look.clone()),
                Some("the report counted no branch".to_owned()),
            );
            continue;
        }
        let mut in_scope = String::new();
        let (covered, total) = if let Some(scope) = rule.scope {
            let Some([covered, total, matched, kept]) = scoped(rule.metric, scope, report, repository, &mut collector)?
            else {
                continue;
            };
            in_scope = format!("{matched} of {kept} packages in the scope; ");
            (covered, total)
        } else if rule.metric == Metric::Branch {
            (report.branches_covered.unwrap_or(0), report.branches_total.unwrap_or(0))
        } else {
            (report.lines_covered, report.lines_total)
        };
        if total <= 0 {
            let detail = if rule.scope.is_some() {
                format!("{in_scope}they count no {}", rule.metric.wire_name())
            } else {
                "the report counted nothing".to_owned()
            };
            collector.missing(repository, None, NoDataReason::StepAbsent, Some(report.look.clone()), Some(detail));
            continue;
        }
        covered_sum = covered_sum.saturating_add(covered);
        total_sum = total_sum.saturating_add(total);
        let ratio = format!("{in_scope}{covered} of {total} {} covered", rule.metric.plural());
        if rule.aggregation == Aggregation::PerRepository {
            let failures = if rule.minimum_ratio.at_least(covered, total) {
                Vec::new()
            } else {
                vec![format!("{ratio}, under {}", rule.minimum_ratio.percent())]
            };
            collector.examined(repository, None, report.look.clone(), failures, Some(ratio));
        } else {
            collector.examined_unjudged(repository, report.look.clone(), ratio);
        }
    }
    let mut project_unmet = Vec::new();
    if rule.aggregation == Aggregation::ProjectWeighted
        && collector.complete()
        && !rule.minimum_ratio.at_least(covered_sum, total_sum)
    {
        project_unmet.push(format!(
            "the project's {covered_sum} of {total_sum} {} covered is under {}",
            rule.metric.plural(),
            rule.minimum_ratio.percent()
        ));
    }
    // A scoped pass states its figures too: the document a reviewer signs shows the filter beside the figure.
    let what = format!(
        "{} coverage of at least {}{}",
        rule.metric.wire_name(),
        rule.minimum_ratio.percent(),
        rule.scope.map_or_else(String::new, |scope| format!(" over {}", scope.describe()))
    );
    collector.outcome(project_unmet, Vec::new(), &what, rule.scope.is_some())
}

/// The scope's figure on one repository — covered, total, packages matched, packages kept — or `None`, already
/// reported to the collector. Never the totals in the scope's place.
fn scoped(
    metric: Metric,
    scope: &crate::coverage_scope::CoverageScope,
    report: &CoverageReport,
    repository: i64,
    collector: &mut Collector,
) -> Result<Option<[i64; 4]>, Defect> {
    match &report.packages {
        Packages::NotRead => {
            Err(Defect("A scoped coverage rule was handed a report whose packages were not read.".to_owned()))
        }
        Packages::Unrecorded => {
            collector.missing(
                repository,
                None,
                NoDataReason::PackagesUnrecorded,
                Some(report.look.clone()),
                Some(format!(
                    "the import predates per-package counts: re-import the report to measure {}",
                    scope.describe()
                )),
            );
            Ok(None)
        }
        Packages::NotKept(why) => {
            collector.missing(
                repository,
                None,
                NoDataReason::PackagesNotKept,
                Some(report.look.clone()),
                Some(why.clone()),
            );
            Ok(None)
        }
        Packages::Kept(packages) => {
            let matched: Vec<_> = packages.iter().filter(|part| scope.matches(&part.path)).collect();
            if matched.is_empty() {
                collector.missing(
                    repository,
                    None,
                    NoDataReason::ScopeMatchesNothing,
                    Some(report.look.clone()),
                    Some(format!(
                        "none of the report's {} {} is in {}",
                        packages.len(),
                        if packages.len() == 1 { "package" } else { "packages" },
                        scope.describe()
                    )),
                );
                return Ok(None);
            }
            let (mut covered, mut total) = (0i64, 0i64);
            for part in &matched {
                let (part_covered, part_total) = if metric == Metric::Branch {
                    (part.branches_covered.unwrap_or(0), part.branches_total.unwrap_or(0))
                } else {
                    (part.lines_covered, part.lines_total)
                };
                covered = covered.saturating_add(part_covered);
                total = total.saturating_add(part_total);
            }
            let count = |length: usize| i64::try_from(length).unwrap_or(i64::MAX);
            Ok(Some([covered, total, count(matched.len()), count(packages.len())]))
        }
    }
}

fn tests(
    names: &[String],
    minimum_tests: i32,
    facts: &MeasurementFacts,
    repositories: &[i64],
    since: Instant,
) -> Result<Measurement, Defect> {
    let mut collector = Collector::default();
    let patterns: Vec<SuitePattern> = names.iter().map(|name| SuitePattern::of(name)).collect();
    let several = names.len() > 1;
    'repositories: for &repository in repositories {
        let Some(report) = facts.tests.get(&repository) else {
            collector.add(repository, None, missing(NoDataReason::NeverExamined, None));
            continue;
        };
        if report.look.at < since {
            collector.add(repository, None, missing(NoDataReason::Stale, Some(report.look.clone())));
            continue;
        }
        // Each pattern on its own suites: a large unit suite must not stand in for an absent functional one.
        let mut unmet = Vec::new();
        let mut ran_per = Vec::new();
        for (pattern, named) in patterns.iter().zip(names) {
            let matched: Vec<_> = report.suites.iter().filter(|suite| pattern.matches(suite.name.as_deref())).collect();
            if matched.is_empty() {
                collector.missing(
                    repository,
                    None,
                    NoDataReason::SuiteNotFound,
                    Some(report.look.clone()),
                    Some(format!("no suite matches {named}")),
                );
                continue 'repositories;
            }
            let ran: i64 = matched
                .iter()
                .map(|suite| i64::from(suite.tests).saturating_sub(i64::from(suite.skipped)))
                .fold(0, i64::saturating_add);
            let prefix = if several { format!("{named}: ") } else { String::new() };
            let suites =
                |count: usize, one: &str, many: &str| format!("{count} {}", if count == 1 { one } else { many });
            if ran <= 0 {
                collector.missing(
                    repository,
                    None,
                    NoDataReason::NoTestRan,
                    Some(report.look.clone()),
                    Some(format!("{prefix}{} and ran no test", suites(matched.len(), "suite matches", "suites match"))),
                );
                continue 'repositories;
            }
            let failures: i64 = matched.iter().map(|suite| i64::from(suite.failures)).fold(0, i64::saturating_add);
            let errors: i64 = matched.iter().map(|suite| i64::from(suite.errors)).fold(0, i64::saturating_add);
            if failures > 0 || errors > 0 {
                unmet.push(format!("{prefix}{failures} failed and {errors} errored"));
            }
            if ran < i64::from(minimum_tests) {
                unmet.push(format!("{prefix}{ran} ran, fewer than {minimum_tests}"));
            }
            ran_per.push(format!("{prefix}{}, {ran} tests ran", suites(matched.len(), "suite", "suites")));
        }
        collector.examined(repository, None, report.look.clone(), unmet, Some(ran_per.join("; ")));
    }
    collector.outcome(Vec::new(), Vec::new(), &format!("suites matching {} passed", names.join(" and ")), false)
}

const INVENTORY_ABSENT: &str =
    "its newest analysed scan no longer holds its SBOM and its inventory lists nothing — scan it again";

/// What the evidence says of a version the SBOM does not state: Syft cannot see a version a parent POM or a BOM
/// manages; an SBOM the build itself produced resolves it.
const MANAGED_ELSEWHERE: &str = "version managed outside the SBOM (a parent POM or a BOM, for one) — import an SBOM \
                                 produced by the build, which states it";

/// How many packages a prefix's listing names before it counts the rest: the evidence is read, not mined.
const LISTED_PACKAGES: usize = 20;

fn components_versions(
    allowed_components: &[AllowedComponent],
    facts: &MeasurementFacts,
    repositories: &[i64],
    since: Instant,
) -> Result<Measurement, Defect> {
    let scoped = facts.scopes.get(VULNERABILITY);
    let mut collector = Collector::default();
    let empty = Vec::new();
    for &repository in repositories {
        let about = scoped.and_then(|scoped| scoped.get(&repository));
        let state = classify(about, since);
        let ScopeState::Examined { look, .. } = state else {
            collector.add(repository, None, state);
            continue;
        };
        // Read as component_present reads it: the inventory outlives the payload, and an empty one beside a purged
        // payload is a list nobody can vouch for.
        let listed = facts.components.get(&repository).unwrap_or(&empty);
        if inventory_absent(listed, about) {
            collector.missing(
                repository,
                None,
                NoDataReason::InventoryAbsent,
                Some(look),
                Some(INVENTORY_ABSENT.to_owned()),
            );
            continue;
        }
        let mut unmet = Vec::new();
        let mut found = Vec::new();
        let mut unrecorded = Vec::new();
        for allowed in allowed_components {
            let occurrences: Vec<&Component> =
                listed.iter().filter(|component| allowed.names(component.purl.as_deref())).collect();
            if occurrences.is_empty() {
                unmet.push(if allowed.ends_on_separator() {
                    format!(
                        "{} ends on its separator and names no package — bind it without the last character",
                        allowed.purl_prefix
                    )
                } else {
                    format!("{} is not in its SBOM", allowed.purl_prefix)
                });
                continue;
            }
            // A version the SBOM does not state is not a version (decision 0007): read as one, it made the line fail
            // for a module present.
            let versions = sorted_set(occurrences.iter().filter_map(|component| component.stated_version()));
            let unstated = occurrences.iter().filter(|component| component.stated_version().is_none()).count();
            let several = packages(&occurrences).len() > 1;
            if versions.is_empty() {
                unrecorded.push(format!(
                    "{} is in its SBOM with no version stated ({}) — {MANAGED_ELSEWHERE}{}",
                    allowed.purl_prefix,
                    occurrence_count(unstated),
                    if several { format!("; {}", listing(&allowed.purl_prefix, &occurrences)) } else { String::new() }
                ));
                continue;
            }
            // The stated occurrences judge and the rest are named beside them: holding the line at no data would keep
            // every multi-module Maven tree unanswerable.
            found.push(if several {
                listing(&allowed.purl_prefix, &occurrences)
            } else {
                format!(
                    "{} at {}{}",
                    allowed.purl_prefix,
                    versions.join(", "),
                    if unstated > 0 {
                        format!(", and {} with no version stated", occurrence_count(unstated))
                    } else {
                        String::new()
                    }
                )
            });
            let refused: Vec<&str> = versions.iter().copied().filter(|version| !allowed.allows(version)).collect();
            if !refused.is_empty() {
                unmet.push(format!("{} at {}, not an allowed version", allowed.purl_prefix, refused.join(", ")));
            }
        }
        if unmet.is_empty() && !unrecorded.is_empty() {
            let mut details = unrecorded;
            details.extend(found);
            collector.missing(repository, None, NoDataReason::VersionUnrecorded, Some(look), Some(details.join("; ")));
            continue;
        }
        // A failure stated by the SBOM stands on its own: the unrecorded packages go beside it.
        found.extend(unrecorded);
        collector.examined(repository, None, look, unmet, Some(found.join("; ")));
    }
    let declared = allowed_components.len();
    collector.outcome(
        Vec::new(),
        Vec::new(),
        &format!(
            "{declared} {} at allowed versions",
            if declared == 1 { "declared package" } else { "declared packages" }
        ),
        false,
    )
}

fn present(
    prefixes: &[String],
    facts: &MeasurementFacts,
    repositories: &[i64],
    since: Instant,
) -> Result<Measurement, Defect> {
    let scoped = facts.scopes.get(VULNERABILITY);
    let mut collector = Collector::default();
    let empty = Vec::new();
    for &repository in repositories {
        let about = scoped.and_then(|scoped| scoped.get(&repository));
        let state = classify(about, since);
        let ScopeState::Examined { look, .. } = state else {
            collector.add(repository, None, state);
            continue;
        };
        let listed = facts.components.get(&repository).unwrap_or(&empty);
        if inventory_absent(listed, about) {
            collector.missing(
                repository,
                None,
                NoDataReason::InventoryAbsent,
                Some(look),
                Some(INVENTORY_ABSENT.to_owned()),
            );
            continue;
        }
        let mut unmet = Vec::new();
        let mut found = Vec::new();
        for prefix in prefixes {
            let occurrences: Vec<&Component> =
                listed.iter().filter(|component| component::names(prefix, component.purl.as_deref())).collect();
            if occurrences.is_empty() {
                unmet.push(if component::ends_on_separator(prefix) {
                    format!("{prefix} ends on its separator and names no package — bind it without the last character")
                } else {
                    format!("{prefix} is not in its SBOM")
                });
                continue;
            }
            found.push(listing(prefix, &occurrences));
        }
        collector.examined(repository, None, look, unmet, Some(found.join("; ")));
    }
    let declared = prefixes.len();
    collector.outcome(
        Vec::new(),
        Vec::new(),
        &format!(
            "{declared} {} present, whatever the version",
            if declared == 1 { "declared package" } else { "declared packages" }
        ),
        false,
    )
}

/// Whether a component rule has nothing to read on a repository: an empty inventory beside a purged payload. Both
/// component kinds ask this one question, so that they never disagree on one SBOM.
fn inventory_absent(listed: &[Component], facts: Option<&ScopeFacts>) -> bool {
    listed.is_empty() && !matches!(facts, Some(ScopeFacts::Scanned(scanned)) if scanned.sbom_stored)
}

/// The packages a prefix matched, each with the versions its occurrences state, in package order, at most
/// [`LISTED_PACKAGES`] of them.
fn listing(prefix: &str, occurrences: &[&Component]) -> String {
    let by_package = packages(occurrences);
    if let [only] = by_package.as_slice() {
        return described(only);
    }
    let named: Vec<String> = by_package.iter().take(LISTED_PACKAGES).map(described).collect();
    let rest = by_package.len().saturating_sub(named.len());
    format!(
        "{prefix} matches {} packages: {}{}",
        by_package.len(),
        named.join(", "),
        if rest > 0 { format!(", and {rest} more") } else { String::new() }
    )
}

/// One package and the versions its occurrences state.
fn described((package, occurrences): &(String, Vec<&Component>)) -> String {
    let stated = sorted_set(occurrences.iter().filter_map(|component| component.stated_version()));
    let unstated = occurrences.iter().any(|component| component.stated_version().is_none());
    if stated.is_empty() {
        return format!("{package} with no version stated");
    }
    format!("{package} at {}{}", stated.join(", "), if unstated { " and with none stated" } else { "" })
}

/// The occurrences by package — the package URL without its version, qualifiers or subpath — in a `TreeMap`'s order.
fn packages<'a>(occurrences: &[&'a Component]) -> Vec<(String, Vec<&'a Component>)> {
    let mut by_package: Vec<(String, Vec<&'a Component>)> = Vec::new();
    for &component in occurrences {
        let purl = component.purl.as_deref().unwrap_or("");
        let end = purl.find(['@', '?', '#']).unwrap_or(purl.len());
        let package = purl.get(..end).unwrap_or(purl).to_owned();
        match by_package.iter_mut().find(|(known, _)| *known == package) {
            Some((_, listed)) => listed.push(component),
            None => by_package.push((package, vec![component])),
        }
    }
    by_package.sort_by(|left, right| java::compare_utf16(&left.0, &right.0));
    by_package
}

/// A `TreeSet<String>` of these, in its order.
fn sorted_set<'a>(values: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let mut sorted: Vec<&str> = values.collect();
    sorted.sort_by(|left, right| java::compare_utf16(left, right));
    sorted.dedup();
    sorted
}

struct Review<'a> {
    minimum_approvals: i32,
    window_days: i32,
    minimum_ratio: Ratio,
    branch: Option<&'a str>,
}

/// How changes reach each repository's branch, as the newest reading of its forge within the age recorded it. A
/// configuration that requires the approvals passes on its own; otherwise the history decides. A window with nothing
/// merged is no data, never a pass; a history cut short, or shorter than the window, is no data too.
fn change_review(
    rule: &Review<'_>,
    facts: &MeasurementFacts,
    repositories: &[i64],
    since: Instant,
) -> Result<Measurement, Defect> {
    let mut collector = Collector::default();
    for &repository in repositories {
        match facts.reviews.get(&repository) {
            None => collector.missing(
                repository,
                None,
                NoDataReason::NeverExamined,
                None,
                Some("no reading of its forge yet: the change-review measurement runs hourly".to_owned()),
            ),
            Some(ReviewFacts::Unlinked { look, why }) => {
                collector.missing(repository, None, NoDataReason::ForgeUnlinked, Some(look.clone()), Some(why.clone()));
            }
            Some(ReviewFacts::Unreadable { look, why }) => {
                if look.at < since {
                    collector.missing(repository, None, NoDataReason::Stale, Some(look.clone()), None);
                } else {
                    collector.missing(
                        repository,
                        None,
                        NoDataReason::ForgeUnreadable,
                        Some(look.clone()),
                        Some(why.clone()),
                    );
                }
            }
            Some(ReviewFacts::Read { look, evidence }) => {
                reviewed(rule, &mut collector, repository, look, evidence, since)?
            }
        }
    }
    let what = format!(
        "merged changes approved by at least {}{}, in {}{}",
        peers(rule.minimum_approvals),
        if rule.minimum_ratio.is_one() {
            ", every one".to_owned()
        } else {
            format!(", {} of them", rule.minimum_ratio.percent())
        },
        days(rule.window_days),
        rule.branch.map_or_else(|| " on the default branch".to_owned(), |branch| format!(" on {branch}"))
    );
    collector.outcome(Vec::new(), Vec::new(), &what, true)
}

fn reviewed(
    rule: &Review<'_>,
    collector: &mut Collector,
    repository: i64,
    look: &Look,
    evidence: &vectispire_domain::checklists::ChangeReviewEvidence,
    since: Instant,
) -> Result<(), Defect> {
    if look.at < since {
        collector.missing(repository, None, NoDataReason::Stale, Some(look.clone()), None);
        return Ok(());
    }
    let place = format!("{} {}", evidence.project, evidence.branch);
    if let Some(settings) = evidence.settings.as_ref().filter(|settings| settings.proves(rule.minimum_approvals)) {
        collector.examined(
            repository,
            None,
            look.clone(),
            Vec::new(),
            Some(format!("{place}: settings: {}", settings.described)),
        );
        return Ok(());
    }
    let settings_note = match &evidence.settings {
        Some(stated) => format!("settings: {}, not enough on their own", stated.described),
        None => format!("settings not read: {}", evidence.settings_unread.as_deref().unwrap_or("unknown")),
    };
    let Some(history) = &evidence.history else {
        collector.missing(
            repository,
            None,
            NoDataReason::ForgeUnreadable,
            Some(look.clone()),
            Some(format!(
                "{place}: history not read: {}; {settings_note}",
                evidence.history_unread.as_deref().unwrap_or("unknown")
            )),
        );
        return Ok(());
    };
    if !history.complete {
        collector.missing(
            repository,
            None,
            NoDataReason::ReviewIncomplete,
            Some(look.clone()),
            Some(format!(
                "{place}: more {} were merged in the window than one reading takes ({} read)",
                evidence.changes(),
                history.changes.len()
            )),
        );
        return Ok(());
    }
    if evidence.window_days < rule.window_days {
        collector.missing(
            repository,
            None,
            NoDataReason::ReviewIncomplete,
            Some(look.clone()),
            Some(format!(
                "{place}: the reading covers {}, the rule {}; the next reading covers it",
                days(evidence.window_days),
                days(rule.window_days)
            )),
        );
        return Ok(());
    }
    let from = look
        .at
        .minus_days(i64::from(rule.window_days))
        .ok_or_else(|| Defect("The window reaches before the time line.".to_owned()))?;
    let merged: Vec<&MergedChange> = history.changes.iter().filter(|change| change.merged_at >= from).collect();
    if merged.is_empty() {
        collector.missing(
            repository,
            None,
            NoDataReason::NoChangeMerged,
            Some(look.clone()),
            Some(format!(
                "{place}: no {} merged in {}",
                evidence.changes().replace("requests", "request"),
                days(rule.window_days)
            )),
        );
        return Ok(());
    }
    let unapproved: Vec<&str> = merged
        .iter()
        .filter(|change| change.peer_approvals < rule.minimum_approvals)
        .map(|change| change.reference.as_str())
        .collect();
    let total = i64::try_from(merged.len()).unwrap_or(i64::MAX);
    let approved = total.saturating_sub(i64::try_from(unapproved.len()).unwrap_or(0));
    let self_approved = merged.iter().filter(|change| change.author_approved).count();
    let counted = format!(
        "{approved} of {total} merged {} approved by {} in {}{}",
        evidence.changes(),
        if rule.minimum_approvals == 1 { "a peer".to_owned() } else { peers(rule.minimum_approvals) },
        days(rule.window_days),
        if self_approved == 0 {
            String::new()
        } else {
            format!(" ({self_approved} approved by their author too, not counted)")
        }
    );
    let mut unmet = Vec::new();
    if !rule.minimum_ratio.at_least(approved, total) {
        let shown: Vec<&str> = unapproved.iter().copied().take(10).collect();
        unmet.push(format!(
            "{counted}, fewer than {}; without: {}{}",
            rule.minimum_ratio.percent(),
            shown.join(", "),
            if unapproved.len() > 10 {
                format!(" and {} more", unapproved.len().saturating_sub(10))
            } else {
                String::new()
            }
        ));
    }
    let detail =
        format!("{place}: {}{settings_note}", if unmet.is_empty() { format!("{counted}; ") } else { String::new() });
    collector.examined(repository, None, look.clone(), unmet, Some(detail));
    Ok(())
}

fn peers(count: i32) -> String {
    format!("{count} {}", if count == 1 { "peer" } else { "peers" })
}

// ------------------------------------------------------------------ thresholds

/// Complete data judged against the thresholds; incomplete data reported, unjudged.
fn judged(
    collector: Collector,
    thresholds: &Thresholds,
    totals: &Counts,
    figures: Vec<Figure>,
    what: &str,
) -> Result<Measurement, Defect> {
    let mut unmet = Vec::new();
    let mut judged = figures;
    let complete = collector.complete();
    for (severity, threshold) in thresholds {
        let (open, resolved) = totals.get(severity).copied().unwrap_or((0, 0));
        let mut failures = Vec::new();
        if let Some(max) = threshold.max_open.filter(|max| open > i64::from(*max)) {
            failures.push(format!("{open} open, more than {max}"));
        }
        // Resolved ÷ (resolved + open): with no issue of the severity, nothing is left to resolve — the scopes looked
        // and found none, which meets the ratio.
        let all = resolved.saturating_add(open);
        if let Some(min) = threshold.min_resolved_ratio.filter(|min| !min.at_least(resolved, all)) {
            failures.push(format!("{resolved} of {all} resolved, under {}", min.percent()));
        }
        judged.push(Figure {
            scope: ALL_SCOPES.to_owned(),
            severity: severity.wire_name().to_owned(),
            open,
            resolved,
            met: if complete { Some(failures.is_empty()) } else { None },
            detail: if failures.is_empty() { None } else { Some(failures.join("; ")) },
        });
        if complete {
            unmet.extend(failures.iter().map(|failure| format!("{}: {failure}", severity.wire_name())));
        }
    }
    collector.outcome(unmet, judged, what, false)
}

/// Open and resolved per severity over the repositories included; a state this version does not know is open.
fn counts(by_repository: Option<&BTreeMap<i64, Vec<IssueCount>>>, included: &[i64]) -> Counts {
    let mut counts: Counts = BTreeMap::new();
    let Some(by_repository) = by_repository else { return counts };
    for repository in included {
        for count in by_repository.get(repository).into_iter().flatten() {
            let pair = counts.entry(Severity::of(Some(&count.severity))).or_insert((0, 0));
            if count.state == "resolved" {
                pair.1 = pair.1.saturating_add(count.count);
            } else {
                pair.0 = pair.0.saturating_add(count.count);
            }
        }
    }
    counts
}

// ------------------------------------------------------------------ gathering the evidence

/// The headlines whose summary carries the first repository's own sentence.
const EXPLAINED: [NoDataReason; 10] = [
    NoDataReason::ForgeUnlinked,
    NoDataReason::ForgeUnreadable,
    NoDataReason::ReviewIncomplete,
    NoDataReason::LanguageNotAnalysed,
    NoDataReason::LanguagesUnrecorded,
    NoDataReason::InventoryAbsent,
    NoDataReason::VersionUnrecorded,
    NoDataReason::PackagesUnrecorded,
    NoDataReason::PackagesNotKept,
    NoDataReason::ScopeMatchesNothing,
];

/// The evidence of one measurement as it is read, repository by repository, and what it adds up to.
#[derive(Debug, Default)]
struct Collector {
    evidence: Vec<RepositoryEvidence>,
    missing: Vec<NoDataReason>,
    unmet: Vec<String>,
    /// A `LinkedHashSet`: in the order first included.
    included: Vec<i64>,
    looks: Vec<Instant>,
}

impl Collector {
    /// One scope over every repository; answers the repositories where it looked. A scope not applicable on every
    /// repository is no data of its own: it looked at nothing.
    fn scope(&mut self, scope: &ToolScope, facts: &MeasurementFacts, repositories: &[i64], since: Instant) -> Vec<i64> {
        let key = scope.key();
        let scoped = facts.scopes.get(&key);
        let mut examined = Vec::new();
        let mut everywhere_not_applicable = true;
        for &repository in repositories {
            let about = scoped.and_then(|scoped| scoped.get(&repository));
            let state = read(scope, about, classify(about, since), &facts.languages);
            if matches!(state, ScopeState::Examined { .. }) && !examined.contains(&repository) {
                examined.push(repository);
            }
            everywhere_not_applicable &= matches!(state, ScopeState::NotApplicable(_));
            self.add(repository, Some(key.clone()), state);
        }
        if everywhere_not_applicable {
            self.missing.push(NoDataReason::NotApplicableAnywhere);
        }
        examined
    }

    fn include(&mut self, repository: i64, at: Instant) {
        if !self.included.contains(&repository) {
            self.included.push(repository);
        }
        self.looks.push(at);
    }

    fn add(&mut self, repository: i64, scope: Option<String>, state: ScopeState) {
        match state {
            ScopeState::Examined { look, note } => {
                let at = look.at;
                self.evidence.push(RepositoryEvidence {
                    repository_id: repository,
                    scope,
                    status: EXAMINED.to_owned(),
                    look: Some(look),
                    met: None,
                    detail: note,
                });
                self.include(repository, at);
            }
            ScopeState::NotApplicable(look) => self.evidence.push(RepositoryEvidence {
                repository_id: repository,
                scope,
                status: NOT_APPLICABLE.to_owned(),
                look: Some(look),
                met: None,
                detail: Some("the plugin applies to none of its languages; left out of the figures".to_owned()),
            }),
            ScopeState::Missing { reason, newest, detail } => self.missing(repository, scope, reason, newest, detail),
        }
    }

    fn missing(
        &mut self,
        repository: i64,
        scope: Option<String>,
        reason: NoDataReason,
        newest: Option<Look>,
        detail: Option<String>,
    ) {
        self.evidence.push(RepositoryEvidence {
            repository_id: repository,
            scope,
            status: reason.wire_name().to_owned(),
            look: newest,
            met: None,
            detail,
        });
        self.missing.push(reason);
    }

    fn examined(
        &mut self,
        repository: i64,
        scope: Option<String>,
        look: Look,
        failures: Vec<String>,
        detail: Option<String>,
    ) {
        let mut details: Vec<String> = detail.filter(|detail| !java::is_blank(detail)).into_iter().collect();
        details.extend(failures.iter().cloned());
        let at = look.at;
        self.evidence.push(RepositoryEvidence {
            repository_id: repository,
            scope,
            status: EXAMINED.to_owned(),
            look: Some(look),
            met: Some(failures.is_empty()),
            detail: if details.is_empty() { None } else { Some(details.join("; ")) },
        });
        self.include(repository, at);
        self.unmet.extend(failures.into_iter().map(|failure| format!("repository {repository}: {failure}")));
    }

    /// Read, and judged over the project rather than here.
    fn examined_unjudged(&mut self, repository: i64, look: Look, detail: String) {
        let at = look.at;
        self.evidence.push(RepositoryEvidence {
            repository_id: repository,
            scope: None,
            status: EXAMINED.to_owned(),
            look: Some(look),
            met: None,
            detail: Some(detail),
        });
        self.include(repository, at);
    }

    fn complete(&self) -> bool {
        self.missing.is_empty()
    }

    /// Where a headline's words alone do not say what to do, the first repository's own sentence.
    fn first_reason(&self, headline: NoDataReason) -> String {
        if !EXPLAINED.contains(&headline) {
            return String::new();
        }
        self.evidence
            .iter()
            .find(|line| line.status == headline.wire_name() && line.detail.is_some())
            .map_or_else(String::new, |line| {
                format!("; repository {}, {}", line.repository_id, line.detail.as_deref().unwrap_or(""))
            })
    }

    /// `pass_figures`: whether a pass names each repository's figure, as a failure does.
    fn outcome(
        self,
        project_unmet: Vec<String>,
        figures: Vec<Figure>,
        what: &str,
        pass_figures: bool,
    ) -> Result<Measurement, Defect> {
        let as_of = self.looks.iter().min().copied();
        if let Some(headline) = self.missing.iter().min().copied() {
            let distinct = |lines: &mut dyn Iterator<Item = &RepositoryEvidence>| {
                let mut ids: Vec<i64> = Vec::new();
                for line in lines {
                    if !ids.contains(&line.repository_id) {
                        ids.push(line.repository_id);
                    }
                }
                ids.len()
            };
            let lacking = distinct(
                &mut self.evidence.iter().filter(|line| line.status != EXAMINED && line.status != NOT_APPLICABLE),
            );
            let total = distinct(&mut self.evidence.iter());
            let summary = if headline == NoDataReason::NotApplicableAnywhere && lacking == 0 {
                "No data (not_applicable_anywhere): the plugin applies to no repository of the project.".to_owned()
            } else {
                format!(
                    "No data ({}) for {what}: {lacking} of {total} repositories without evidence{}.",
                    headline.wire_name(),
                    self.first_reason(headline)
                )
            };
            return Measurement::new(
                MeasurementOutcome::NoData,
                Some(headline),
                as_of,
                self.evidence,
                figures,
                summary,
            );
        }
        let mut failures = self.unmet;
        failures.extend(project_unmet);
        if !failures.is_empty() {
            let shown: Vec<&str> = failures.iter().map(String::as_str).take(10).collect();
            let summary = format!(
                "Fail, {what}: {}{}",
                shown.join("; "),
                if failures.len() > 10 {
                    format!("; and {} more.", failures.len().saturating_sub(10))
                } else {
                    ".".to_owned()
                }
            );
            return Measurement::new(MeasurementOutcome::Fail, None, as_of, self.evidence, figures, summary);
        }
        let passed: Vec<String> = if pass_figures {
            self.evidence
                .iter()
                .filter_map(|line| {
                    line.detail.as_ref().map(|detail| format!("repository {}: {detail}", line.repository_id))
                })
                .collect()
        } else {
            Vec::new()
        };
        let included = self.included.len();
        let summary = format!(
            "Pass, {what}, on {included} {}{}{}.",
            if included == 1 { "repository" } else { "repositories" },
            as_of.and_then(Instant::to_java_string).map_or_else(String::new, |at| format!(", as of {at}")),
            if passed.is_empty() {
                String::new()
            } else {
                let shown: Vec<&str> = passed.iter().map(String::as_str).take(10).collect();
                format!(
                    ": {}{}",
                    shown.join("; "),
                    if passed.len() > 10 {
                        format!("; and {} more", passed.len().saturating_sub(10))
                    } else {
                        String::new()
                    }
                )
            }
        );
        Measurement::new(MeasurementOutcome::Pass, None, as_of, self.evidence, figures, summary)
    }
}

fn occurrence_count(count: usize) -> String {
    format!("{count} {}", if count == 1 { "occurrence" } else { "occurrences" })
}

fn days(days: i32) -> String {
    format!("{days} {}", if days == 1 { "day" } else { "days" })
}
