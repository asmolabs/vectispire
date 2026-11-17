//! Where this product's findings land in the OWASP Top 10, by rule, and where they cannot — Java's `OwaspCoverage`.
//!
//! The placement first: the categories, the types placed by rule, and the one type that declares its category on
//! the issue. The backlog's `owasp_category` filter places with it, and so do the grid and the weekly flows, so the
//! list a figure opens holds what the figure counted. Comparing the issue's `owasp_category` column alone — what the
//! port did before — put a vulnerability nowhere (it is A06 with no column) and counted a plugin's self-declared
//! category.
//!
//! Then the grid: **four states, because two would lie**. A category with no findings and a category nothing looks
//! at produce the same green; [`State::NotCovered`] says no scanner here can produce a finding there at all, and
//! [`State::NotMeasured`] that one could and has not been allowed to — switched off, or a target in scope whose newest
//! finished scan did not examine it ([`Evidence`], decision 0007). Every line carries its reason as a code and its
//! values ([`CoverageReason`]) and as the English sentence written from them. Held to `reference/compliance/owasp.json`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::finding_type::FindingType;
use crate::instant::Instant;
use crate::language::Language;
use crate::observation::Observation;
use crate::scan_target::ScanTarget;

/// The 2021 edition, in the standard's order: the order a questionnaire reads the grid in.
pub const CATEGORIES: [(&str, &str); 10] = [
    ("A01", "Broken Access Control"),
    ("A02", "Cryptographic Failures"),
    ("A03", "Injection"),
    ("A04", "Insecure Design"),
    ("A05", "Security Misconfiguration"),
    ("A06", "Vulnerable and Outdated Components"),
    ("A07", "Identification and Authentication Failures"),
    ("A08", "Software and Data Integrity Failures"),
    ("A09", "Security Logging and Monitoring Failures"),
    ("A10", "Server-Side Request Forgery"),
];

/// The finding types that place a finding in a category, by rule — Java's `BY_TYPE`.
const BY_TYPE: &[(FindingType, &str)] = &[
    (FindingType::Iac, "A05"),
    (FindingType::Vulnerability, "A06"),
    (FindingType::Eol, "A06"),
    (FindingType::Secret, "A07"),
];

/// The one type whose findings carry their category on the issue rather than in the type: code
/// analysis. A plugin's or an import's finding carrying a category is not placed.
pub const DECLARES_ITS_CATEGORY: FindingType = FindingType::Sast;

/// Whether `code` (already upper-cased) is one of the ten.
pub fn is_category(code: &str) -> bool {
    CATEGORIES.iter().any(|(known, _)| *known == code)
}

/// The ten codes, in order.
pub fn codes() -> impl Iterator<Item = &'static str> {
    CATEGORIES.iter().map(|(code, _)| *code)
}

/// The category a finding of this type belongs to, or nothing when no rule places it.
pub fn category_of(type_: FindingType) -> Option<&'static str> {
    BY_TYPE.iter().find(|(placed, _)| *placed == type_).map(|(_, category)| *category)
}

/// The wire names of the types placed in this category, sorted — empty for one only code analysis reaches.
pub fn types_placed_in(category: &str) -> Vec<&'static str> {
    let mut types: Vec<&'static str> =
        BY_TYPE.iter().filter(|(_, placed)| *placed == category).map(|(type_, _)| type_.wire_name()).collect();
    types.sort_unstable();
    types
}

/// The wire names of the types placed somewhere, sorted.
pub fn types_placed_anywhere() -> Vec<&'static str> {
    let mut types: Vec<&'static str> = BY_TYPE.iter().map(|(type_, _)| type_.wire_name()).collect();
    types.sort_unstable();
    types.dedup();
    types
}

/// Where in the Top 10 a backlog query asks an issue to be placed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwaspPlacement {
    /// In one category, `A01`…`A10`.
    In(String),
    /// In any of the ten.
    Anywhere,
}

/// The category of one category code, as the static the grid's lines carry.
fn category_code(code: &str) -> Option<&'static str> {
    codes().find(|known| *known == code)
}

/// Where one issue lands in the Top 10, by the grid's placement and nothing else — `placementOf`: its type's
/// category, or for code analysis the category its rule declared, when that is one of the ten.
///
/// **Placement, not measurement**: whether a category is measured is a setting of the moment, which a reading of
/// the past does not know; the backlog's `owasp_category` filter selects the same set.
pub fn placement_of(type_: FindingType, declared_category: Option<&str>) -> Option<&'static str> {
    if let Some(category) = category_of(type_) {
        return Some(category);
    }
    if type_ == DECLARES_ITS_CATEGORY { declared_category.and_then(category_code) } else { None }
}

/// The open code findings the grid places in no category — `unplacedCode`: their rule declares no 2021 category and
/// no CWE the standard's lists hold. **Counted, because placed nowhere is not the same as absent.**
///
/// A category that is not one of the ten places nothing and is left in the remainder. Never below zero: two reads,
/// and a finding categorised between them would count as minus one. Java's `long` sums wrap, and so do these.
pub fn unplaced_code<'a>(open_code: i64, open_by_category: impl IntoIterator<Item = (&'a str, i64)>) -> i64 {
    let placed = open_by_category
        .into_iter()
        .filter(|(category, _)| is_category(category))
        .fold(0i64, |sum, (_, count)| sum.wrapping_add(count));
    open_code.wrapping_sub(placed).max(0)
}

/// Whether a target's scans can examine it for this type at all — `examinable`. **An image's scan runs the dependency
/// step alone**: its SBOM gives the vulnerabilities, the components past support and the licences, and nothing reads
/// an image for secrets, infrastructure code or with code analysis.
pub fn examinable(type_: FindingType, target: ScanTarget) -> bool {
    match target {
        ScanTarget::Repository(_) => true,
        ScanTarget::Container(_) => {
            matches!(type_, FindingType::Vulnerability | FindingType::Eol | FindingType::License)
        }
    }
}

/// The Monday at 00:00 UTC of the week `at` falls in; a Monday at midnight is its own week — `CoverageWeek.startOf`.
///
/// **UTC and not the reader's zone**: the weekly record is shared by every reader, and a week cut at each reader's
/// midnight would put Sunday night's capture in a different week for each of them.
pub fn week_start(at: Instant) -> Instant {
    let day = at.epoch_second.div_euclid(Instant::SECONDS_PER_DAY);
    // 1970-01-01 was a Thursday, three days after a Monday.
    let since_monday = day.wrapping_add(3).rem_euclid(7);
    Instant::of_epoch_second(day.wrapping_sub(since_monday).wrapping_mul(Instant::SECONDS_PER_DAY))
}

/// What this deployment can say about one category — `State`, ordered from what needs attention to what does not,
/// so a sort puts *not covered* above *nothing found*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum State {
    /// A scanner covers it and found things.
    Findings,
    /// A scanner covers it and has not looked at this estate — switched off, or a target in scope not examined.
    NotMeasured,
    /// No scanner here can produce a finding in this category at all: a property of the product, not the estate.
    NotCovered,
    /// A scanner covers it, looked, and found nothing.
    NoFinding,
}

/// What one target's newest finished scan says it was examined for — `Evidence`, the ground a category's "nothing
/// found" rests on. **A scan having run is not the question; which of its steps produced is.**
///
/// The constructor normalises as Java's does: a scan that did not finish well examined nothing that can be relied
/// on, and the categories the rules reach are known exactly when the languages they read are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub target: ScanTarget,
    pub observation: Observation,
    examined: Option<BTreeSet<FindingType>>,
    analysed: Option<BTreeSet<Language>>,
    code_reaches: Option<BTreeSet<String>>,
}

impl Evidence {
    /// `examined` is kept only when the observation is [`Observation::Ok`]; `code_reaches` is absent exactly when
    /// `analysed` is, and the empty set when it is present and nothing was said of the categories.
    pub fn new(
        target: ScanTarget,
        observation: Observation,
        examined: Option<BTreeSet<FindingType>>,
        analysed: Option<BTreeSet<Language>>,
        code_reaches: Option<BTreeSet<String>>,
    ) -> Evidence {
        let examined = if observation == Observation::Ok { examined } else { None };
        let code_reaches = if analysed.is_none() { None } else { Some(code_reaches.unwrap_or_default()) };
        Evidence { target, observation, examined, analysed, code_reaches }
    }

    /// A target with no finished scan.
    pub fn never_scanned(target: ScanTarget) -> Evidence {
        Evidence::new(target, Observation::NeverScanned, None, None, None)
    }

    /// The evidence of one finished scan — `Evidence.of`: the tree's languages its rules read, and the categories
    /// today's installed rules of those languages declare. A language the scan's rules did not read is never
    /// credited, which is the direction that would let a category read clean.
    pub fn of(
        target: ScanTarget,
        observation: Observation,
        examined: Option<BTreeSet<FindingType>>,
        detected: Option<&BTreeSet<Language>>,
        sast_rules: Option<&BTreeSet<Language>>,
        declared_by_language: &HashMap<Language, BTreeSet<String>>,
    ) -> Evidence {
        let analysed = match (detected, sast_rules) {
            (Some(detected), Some(rules)) => Some(detected.intersection(rules).copied().collect::<BTreeSet<_>>()),
            _ => None,
        };
        let reaches = analysed.as_ref().map(|languages| {
            languages
                .iter()
                .filter_map(|language| declared_by_language.get(language))
                .flat_map(|categories| categories.iter().cloned())
                .collect()
        });
        Evidence::new(target, observation, examined, analysed, reaches)
    }

    /// The types that scan's steps produced; absent unless it finished well and recorded them.
    pub fn examined(&self) -> Option<&BTreeSet<FindingType>> {
        self.examined.as_ref()
    }

    /// The languages of the tree its code-analysis rules read; absent when either side was not recorded, which is
    /// not the empty set: "nobody counted" is not "no rule reads it".
    pub fn analysed(&self) -> Option<&BTreeSet<Language>> {
        self.analysed.as_ref()
    }

    /// The categories declared by an installed rule written for one of [`analysed`](Self::analysed).
    pub fn code_reaches(&self) -> Option<&BTreeSet<String>> {
        self.code_reaches.as_ref()
    }

    fn examined_for(&self, type_: FindingType) -> bool {
        self.examined.as_ref().is_some_and(|types| types.contains(&type_))
    }
}

/// Why one target was not examined for a category — `Gap`, declared in the order the sentence names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Gap {
    NeverScanned,
    LastScanFailed,
    Unrecorded,
    StepAbsent,
    LanguagesUnrecorded,
    NoRuleForItsLanguages,
}

impl Gap {
    /// The words the English sentence names it with.
    pub fn words(self) -> &'static str {
        match self {
            Gap::NeverScanned => "never finished a scan",
            Gap::LastScanFailed => "whose latest scan failed",
            Gap::Unrecorded => "whose latest scan predates the record of what it examined",
            Gap::StepAbsent => "whose latest scan did not complete that step",
            Gap::LanguagesUnrecorded => "whose latest scan did not record its languages, or its rules'",
            Gap::NoRuleForItsLanguages => "in whose languages no installed rule declares this category",
        }
    }
}

/// Where a category's examination comes from, for one grid: the types placed in it, or code analysis.
enum Source<'a> {
    /// The types placed in the category that the settings measure.
    Types(&'a [FindingType]),
    Code(&'a str),
}

impl Source<'_> {
    fn applies_to(&self, target: ScanTarget) -> bool {
        match self {
            Source::Types(types) => types.iter().any(|type_| examinable(*type_, target)),
            Source::Code(_) => matches!(target, ScanTarget::Repository(_)),
        }
    }

    /// Why this target was not examined for it, or nothing when it was.
    fn gap_of(&self, evidence: &Evidence) -> Option<Gap> {
        match evidence.observation {
            Observation::Ok => {}
            Observation::LastScanFailed => return Some(Gap::LastScanFailed),
            // In progress does not reach here — the evidence is the newest *finished* scan — and would be no
            // examination if it did.
            Observation::NeverScanned | Observation::InProgress => return Some(Gap::NeverScanned),
        }
        if evidence.examined.is_none() {
            return Some(Gap::Unrecorded);
        }
        match self {
            // Every type this target can be examined for: A06 is "vulnerable *and* outdated", and an end-of-life
            // lookup that failed leaves the second half unlooked at.
            Source::Types(types) => {
                let examined = types
                    .iter()
                    .filter(|type_| examinable(**type_, evidence.target))
                    .all(|type_| evidence.examined_for(*type_));
                (!examined).then_some(Gap::StepAbsent)
            }
            Source::Code(category) => {
                if !evidence.examined_for(FindingType::Sast) {
                    Some(Gap::StepAbsent)
                } else {
                    match &evidence.code_reaches {
                        None => Some(Gap::LanguagesUnrecorded),
                        Some(reaches) if reaches.contains(*category) => None,
                        Some(_) => Some(Gap::NoRuleForItsLanguages),
                    }
                }
            }
        }
    }
}

/// What the deployment measures, as opposed to what it found — `Measurement`.
///
/// `code_analysis_enabled` is the deployment's half of code analysis (on, and more than the shipped rule installed);
/// whether a rule reaches a target's languages is the evidence's. `declared_by_rules` are the categories the
/// *installed* rules declare — what makes an empty category honest. `targets` is the evidence of every target the
/// counts were read over: one the counts cover and this omits would be taken as examined.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Measurement {
    pub end_of_life_enabled: bool,
    pub code_analysis_enabled: bool,
    pub open_by_type: HashMap<FindingType, i64>,
    pub declared_by_rules: BTreeSet<String>,
    pub open_by_category: HashMap<String, i64>,
    pub targets: Vec<Evidence>,
}

/// How many of the targets a category applies to were not examined for it, for one reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapCount {
    pub gap: Gap,
    pub targets: i64,
}

/// Why a line reads what it reads, as a token rather than a sentence (decision 0019) — `ReasonCode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    NoScanner,
    CodeAnalysisOff,
    /// No category is placed by switchable types alone today, so the grid never produces it.
    DetectionOff,
    DetectionAndCodeAnalysisOff,
    OpenFindings,
    NothingScanned,
    TargetKindNotExamined,
    CodeAnalysisReadsRepositoriesOnly,
    NoExaminableTargetInScope,
    NoRepositoryInScope,
    ExaminedNothingOpen,
    CodeExaminedNothingOpen,
    TargetsNotExamined,
    RepositoriesNotExamined,
}

/// The reason of one line with the values its sentence is made of — `CoverageReason`. `types` are wire names in the
/// order the sentence names them; `missing` and `applicable` are present only for the two codes of targets not
/// examined, and `gaps` (in [`Gap`]'s order) sum to `missing`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageReason {
    pub code: ReasonCode,
    pub types: Vec<String>,
    pub missing: Option<i64>,
    pub applicable: Option<i64>,
    pub gaps: Vec<GapCount>,
}

const CODE_OFF: &str = "code analysis is off, or only the rule this product ships is installed";

impl CoverageReason {
    fn of(code: ReasonCode) -> CoverageReason {
        CoverageReason { code, types: Vec::new(), missing: None, applicable: None, gaps: Vec::new() }
    }

    fn naming(code: ReasonCode, types: &[FindingType]) -> CoverageReason {
        CoverageReason { types: wire_names(types), ..CoverageReason::of(code) }
    }

    fn unexamined(
        code: ReasonCode,
        types: &[FindingType],
        applicable: usize,
        gaps: &BTreeMap<Gap, i64>,
    ) -> CoverageReason {
        let gaps: Vec<GapCount> = gaps.iter().map(|(gap, targets)| GapCount { gap: *gap, targets: *targets }).collect();
        let missing = gaps.iter().fold(0i64, |sum, gap| sum.wrapping_add(gap.targets));
        CoverageReason {
            code,
            types: wire_names(types),
            missing: Some(missing),
            applicable: Some(i64::try_from(applicable).unwrap_or(i64::MAX)),
            gaps,
        }
    }

    /// The reason in English — the line's `because`, which exports quote as it stands. A rendering of the code and
    /// its values, never a second source.
    pub fn sentence(&self) -> String {
        let what = self.types.join(", ");
        match self.code {
            ReasonCode::NoScanner => "No scanner in this deployment produces a finding in this category.".to_owned(),
            ReasonCode::CodeAnalysisOff => format!("{}.", capitalise(CODE_OFF)),
            ReasonCode::DetectionOff => {
                format!("Detection is switched off for {what}, so this category is not measured.")
            }
            ReasonCode::DetectionAndCodeAnalysisOff => {
                format!("Detection is switched off for {what}, and {CODE_OFF}, so this category is not measured.")
            }
            ReasonCode::OpenFindings => "Open findings placed here by rule.".to_owned(),
            ReasonCode::NothingScanned => {
                "Nothing has been scanned yet, so no finding of this category could exist.".to_owned()
            }
            ReasonCode::TargetKindNotExamined => format!(
                "Nothing here examines this kind of target for {what}: an image's scan reads its dependencies only."
            ),
            ReasonCode::CodeAnalysisReadsRepositoriesOnly => {
                "Only code analysis places findings here, and it reads repositories, not images.".to_owned()
            }
            ReasonCode::NoExaminableTargetInScope => format!(
                "No target in this scope can be examined for {what}: an image's scan reads its dependencies only, and \
                 this scope holds no repository."
            ),
            ReasonCode::NoRepositoryInScope => {
                "Only code analysis places findings here, and this scope holds no repository for it to read.".to_owned()
            }
            ReasonCode::ExaminedNothingOpen => nothing_open(&what),
            ReasonCode::CodeExaminedNothingOpen => nothing_open("code analysis"),
            ReasonCode::TargetsNotExamined => self.unexamined_sentence(&what, "target", "targets"),
            ReasonCode::RepositoriesNotExamined => {
                self.unexamined_sentence("code analysis", "repository", "repositories")
            }
        }
    }

    /// "2 of 3 targets…", and why each was not. Java concatenates the boxed counts, so an absent one reads "null".
    fn unexamined_sentence(&self, what: &str, one: &str, many: &str) -> String {
        let why =
            self.gaps.iter().map(|gap| format!("{} {}", gap.targets, gap.gap.words())).collect::<Vec<_>>().join(", ");
        let shown = |count: Option<i64>| count.map_or_else(|| "null".to_owned(), |count| count.to_string());
        format!(
            "{} of {} {} this category applies to {} not examined for it by {what} ({why}), so a zero here would not \
             be a result.",
            shown(self.missing),
            shown(self.applicable),
            if self.applicable == Some(1) { one } else { many },
            if self.missing == Some(1) { "was" } else { "were" },
        )
    }
}

fn nothing_open(what: &str) -> String {
    format!("Scanned by {what} — the latest scan of every target it applies to examined it — with nothing open.")
}

fn capitalise(sentence: &str) -> String {
    let mut chars = sentence.chars();
    chars.next().map_or_else(String::new, |first| first.to_uppercase().chain(chars).collect())
}

fn wire_names(types: &[FindingType]) -> Vec<String> {
    types.iter().map(|type_| type_.wire_name().to_owned()).collect()
}

/// One category of one grid — `CoverageLine`. `findings` is zero unless the state is [`State::Findings`];
/// `because` is `reason`'s sentence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageLine {
    pub id: &'static str,
    pub title: &'static str,
    pub state: State,
    pub findings: i64,
    pub because: String,
    pub reason: CoverageReason,
}

impl CoverageLine {
    fn of(id: &'static str, title: &'static str, state: State, findings: i64, reason: CoverageReason) -> CoverageLine {
        CoverageLine { id, title, state, findings, because: reason.sentence(), reason }
    }
}

/// A grid, in the standard's order — `Grid`. **Read `covered` first**: how many of the ten anything here can speak
/// to at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Grid {
    pub lines: Vec<CoverageLine>,
    pub covered: i32,
    pub with_findings: i32,
    pub unmeasured: i32,
}

/// A target's grid asked of anything but one target — Java's `IllegalArgumentException`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("A target's grid is read over that one target.")]
pub struct NotOneTarget;

/// The grid of a scope, in the standard's order — `assess`.
pub fn assess(measurement: &Measurement) -> Grid {
    grid(measurement, false)
}

/// One target's own grid — `assessTarget`, the line the weekly record keeps for it. **One difference from a scope of
/// that one target**, which lets a scope's grid be the fold of its targets' ([`across_targets`]): a category the
/// target cannot be examined for at all reads [`State::NotCovered`] here, so a fold can leave it aside.
pub fn assess_target(measurement: &Measurement) -> Result<Grid, NotOneTarget> {
    if measurement.targets.len() != 1 {
        return Err(NotOneTarget);
    }
    Ok(grid(measurement, true))
}

fn grid(measurement: &Measurement, one_target: bool) -> Grid {
    let lines: Vec<CoverageLine> =
        CATEGORIES.iter().map(|(id, title)| line(id, title, measurement, one_target)).collect();
    let count = |state: fn(State) -> bool| {
        i32::try_from(lines.iter().filter(|line| state(line.state)).count()).unwrap_or(i32::MAX)
    };
    Grid {
        covered: count(|state| state != State::NotCovered),
        with_findings: count(|state| state == State::Findings),
        unmeasured: count(|state| state == State::NotMeasured),
        lines,
    }
}

fn measures(type_: FindingType, measurement: &Measurement) -> bool {
    match type_ {
        FindingType::Eol => measurement.end_of_life_enabled,
        _ => true,
    }
}

fn line(id: &'static str, title: &'static str, measurement: &Measurement, one_target: bool) -> CoverageLine {
    // In the type's declaration order, as Java's `sorted()` orders the enum.
    let mut types: Vec<FindingType> =
        BY_TYPE.iter().filter(|(_, category)| *category == id).map(|(type_, _)| *type_).collect();
    types.sort_unstable();

    // **Two ways in, and they are not the same question.** A type covers a category by rule, for every estate; code
    // analysis covers one because a rule somebody installed says so, read rather than assumed.
    let declared = measurement.declared_by_rules.contains(id);
    if types.is_empty() && !declared {
        return CoverageLine::of(id, title, State::NotCovered, 0, CoverageReason::of(ReasonCode::NoScanner));
    }

    // A type that is switched off measures nothing, and its zero is not a result.
    let measured: Vec<FindingType> = types.iter().copied().filter(|type_| measures(*type_, measurement)).collect();
    let code_measured = declared && measurement.code_analysis_enabled;
    if measured.is_empty() && !code_measured {
        return CoverageLine::of(id, title, State::NotMeasured, 0, why_unmeasured(&types, declared));
    }

    // **An open finding is a fact, whatever examined the target since**: findings decide first, the evidence decides
    // only whether a zero means anything. `long` sums, wrapping as Java's do.
    let by_types = measured
        .iter()
        .fold(0i64, |sum, type_| sum.wrapping_add(measurement.open_by_type.get(type_).copied().unwrap_or(0)));
    let by_code = if code_measured { measurement.open_by_category.get(id).copied().unwrap_or(0) } else { 0 };
    let findings = by_types.wrapping_add(by_code);
    if findings > 0 {
        return CoverageLine::of(id, title, State::Findings, findings, CoverageReason::of(ReasonCode::OpenFindings));
    }

    // A category a type places is examined by those types; the rules declaring it too add findings, not a condition.
    let source = if measured.is_empty() { Source::Code(id) } else { Source::Types(&measured) };
    let by_types = matches!(source, Source::Types(_));

    if measurement.targets.is_empty() {
        return CoverageLine::of(id, title, State::NotMeasured, 0, CoverageReason::of(ReasonCode::NothingScanned));
    }
    let applicable: Vec<&Evidence> =
        measurement.targets.iter().filter(|evidence| source.applies_to(evidence.target)).collect();
    if applicable.is_empty() {
        if one_target {
            let reason = if by_types {
                CoverageReason::naming(ReasonCode::TargetKindNotExamined, &measured)
            } else {
                CoverageReason::of(ReasonCode::CodeAnalysisReadsRepositoriesOnly)
            };
            return CoverageLine::of(id, title, State::NotCovered, 0, reason);
        }
        return if by_types {
            CoverageLine::of(
                id,
                title,
                State::NotMeasured,
                0,
                CoverageReason::naming(ReasonCode::NoExaminableTargetInScope, &measured),
            )
        } else {
            CoverageLine::of(id, title, State::NotCovered, 0, CoverageReason::of(ReasonCode::NoRepositoryInScope))
        };
    }

    let mut gaps: BTreeMap<Gap, i64> = BTreeMap::new();
    for gap in applicable.iter().filter_map(|evidence| source.gap_of(evidence)) {
        let count = gaps.entry(gap).or_insert(0);
        *count = count.wrapping_add(1);
    }
    if gaps.is_empty() {
        let reason = if by_types {
            CoverageReason::naming(ReasonCode::ExaminedNothingOpen, &measured)
        } else {
            CoverageReason::of(ReasonCode::CodeExaminedNothingOpen)
        };
        return CoverageLine::of(id, title, State::NoFinding, 0, reason);
    }
    let reason = if by_types {
        CoverageReason::unexamined(ReasonCode::TargetsNotExamined, &measured, applicable.len(), &gaps)
    } else {
        CoverageReason::unexamined(ReasonCode::RepositoriesNotExamined, &[], applicable.len(), &gaps)
    };
    CoverageLine::of(id, title, State::NotMeasured, 0, reason)
}

/// Why a covered category is nonetheless unmeasured, naming the half that is off — both, when both are, so that
/// nobody is sent to switch on a detector that was already running.
fn why_unmeasured(types: &[FindingType], declared: bool) -> CoverageReason {
    if types.is_empty() {
        return CoverageReason::of(ReasonCode::CodeAnalysisOff);
    }
    CoverageReason::naming(
        if declared { ReasonCode::DetectionAndCodeAnalysisOff } else { ReasonCode::DetectionOff },
        types,
    )
}

/// One category of one grid with the settled findings counted apart — `Split`, the line the weekly record keeps
/// per target. `open` is the grid's own figure; `settled` (accepted, not applicable, a false positive) is kept apart
/// rather than dropped or added in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Split {
    pub id: String,
    pub state: State,
    pub open: i64,
    pub settled: i64,
}

/// The two readings of one estate side by side — `split`: the difference of two grids, never below zero, and not a
/// third rule, so the two figures cannot disagree about where a finding lands.
pub fn split(unsettled: &Grid, all: &Grid) -> Vec<Split> {
    let with_settled: HashMap<&str, i64> = all.lines.iter().map(|line| (line.id, line.findings)).collect();
    unsettled
        .lines
        .iter()
        .map(|line| Split {
            id: line.id.to_owned(),
            state: line.state,
            open: line.findings,
            settled: with_settled.get(line.id).copied().unwrap_or(0).wrapping_sub(line.findings).max(0),
        })
        .collect()
}

/// One category over several targets, from each target's recorded line — `acrossTargets`: the live grid's answer
/// for the same targets, which is what makes a heatmap's last column agree with the grid beside it.
///
/// Open findings anywhere make it [`State::Findings`]; otherwise a [`State::NotCovered`] line is left aside; one
/// [`State::NotMeasured`] line among the rest makes it not measured — "nothing found" over half a scope is the false
/// green; no line left reads not measured for a category a type places, not covered for one only code analysis
/// reaches. Nothing when no target was recorded — never a state invented for nothing.
pub fn across_targets(id: &str, per_target: &[Split]) -> Option<Split> {
    if per_target.is_empty() {
        return None;
    }
    let open = per_target.iter().fold(0i64, |sum, line| sum.wrapping_add(line.open));
    let settled = per_target.iter().fold(0i64, |sum, line| sum.wrapping_add(line.settled));
    if open > 0 {
        return Some(Split { id: id.to_owned(), state: State::Findings, open, settled });
    }
    let applicable: Vec<State> =
        per_target.iter().map(|line| line.state).filter(|state| *state != State::NotCovered).collect();
    let state = if applicable.is_empty() {
        if types_placed_in(id).is_empty() { State::NotCovered } else { State::NotMeasured }
    } else if applicable.iter().all(|state| matches!(state, State::NoFinding | State::Findings)) {
        State::NoFinding
    } else {
        State::NotMeasured
    };
    Some(Split { id: id.to_owned(), state, open: 0, settled })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_types_are_placed_as_java_places_them() {
        assert_eq!(types_placed_in("A06"), vec!["eol", "vulnerability"]);
        assert_eq!(types_placed_in("A05"), vec!["iac"]);
        assert_eq!(types_placed_in("A07"), vec!["secret"]);
        assert!(types_placed_in("A03").is_empty(), "only code analysis reaches injection");
        assert_eq!(types_placed_anywhere(), vec!["eol", "iac", "secret", "vulnerability"]);
        assert_eq!(category_of(FindingType::Sast), None);
        assert_eq!(category_of(FindingType::Plugin), None);
    }

    #[test]
    fn the_ten_are_in_the_standards_order() {
        assert_eq!(codes().collect::<Vec<_>>(), ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]);
        assert!(is_category("A10"));
        assert!(!is_category("A11"));
    }

    const EVERY_STEP: [FindingType; 7] = [
        FindingType::Vulnerability,
        FindingType::Eol,
        FindingType::License,
        FindingType::Secret,
        FindingType::Iac,
        FindingType::Sast,
        FindingType::Quality,
    ];

    fn repository(id: i64, without: Option<FindingType>, reaches: &[&str]) -> Evidence {
        let java = Language::from_wire_name("java").into_iter().collect();
        Evidence::new(
            ScanTarget::Repository(id),
            Observation::Ok,
            Some(EVERY_STEP.into_iter().filter(|type_| Some(*type_) != without).collect()),
            Some(java),
            Some(reaches.iter().map(|category| (*category).to_owned()).collect()),
        )
    }

    fn image(id: i64) -> Evidence {
        let steps = [FindingType::Vulnerability, FindingType::Eol, FindingType::License].into_iter().collect();
        Evidence::new(ScanTarget::Container(id), Observation::Ok, Some(steps), None, None)
    }

    fn state_of(grid: &Grid, id: &str) -> Option<State> {
        grid.lines.iter().find(|line| line.id == id).map(|line| line.state)
    }

    #[test]
    fn an_image_only_scope_is_examined_for_its_dependencies_alone() {
        // `OwaspCoverageEvidenceTest.anImageOnlyScope`, and a target's own line beside it.
        let open = [FindingType::Iac, FindingType::Vulnerability, FindingType::Eol, FindingType::Secret]
            .into_iter()
            .map(|type_| (type_, 0))
            .collect();
        let scope = Measurement {
            end_of_life_enabled: true,
            code_analysis_enabled: true,
            open_by_type: open,
            targets: vec![image(1), image(2)],
            ..Measurement::default()
        };
        let grid = assess(&scope);
        assert_eq!(state_of(&grid, "A06"), Some(State::NoFinding));
        assert_eq!(state_of(&grid, "A07"), Some(State::NotMeasured));
        let own = assess_target(&Measurement { targets: vec![image(1)], ..scope }).ok();
        assert_eq!(own.as_ref().and_then(|grid| state_of(grid, "A07")), Some(State::NotCovered));
    }

    /// **A scope's grid is the fold of its targets' lines** — `theScopeIsTheFoldOfItsTargets`: every scope of up to
    /// three kinds of evidence, three backlogs, both settings of code analysis and end of life, one settled secret on
    /// the first repository. The reference set pins the answers; this pins the property the weekly record rests on.
    #[test]
    fn a_scope_is_the_fold_of_its_targets() {
        let kinds = [
            repository(1, None, &["A03"]),
            repository(2, None, &["A02"]),
            repository(3, Some(FindingType::Secret), &["A03"]),
            Evidence::new(ScanTarget::Repository(4), Observation::LastScanFailed, None, None, None),
            Evidence::never_scanned(ScanTarget::Repository(5)),
            Evidence::new(ScanTarget::Repository(6), Observation::Ok, None, None, None),
            image(7),
            Evidence::never_scanned(ScanTarget::Container(8)),
        ];
        let backlogs: [&[(FindingType, i64)]; 3] =
            [&[], &[(FindingType::Secret, 1)], &[(FindingType::Vulnerability, 2), (FindingType::Eol, 1)]];
        let declared: BTreeSet<String> = ["A02", "A03"].into_iter().map(str::to_owned).collect();
        let mut scopes: Vec<Vec<usize>> = Vec::new();
        for a in 0..kinds.len() {
            scopes.push(vec![a]);
            for b in a + 1..kinds.len() {
                scopes.push(vec![a, b]);
                for c in b + 1..kinds.len() {
                    scopes.push(vec![a, b, c]);
                }
            }
        }
        let mut compared = 0;
        for scope in &scopes {
            for (variant, backlog) in backlogs.iter().enumerate() {
                for code in [true, false] {
                    for end_of_life in [true, false] {
                        let measure =
                            |open: HashMap<FindingType, i64>, by_category: HashMap<String, i64>, targets| Measurement {
                                end_of_life_enabled: end_of_life,
                                code_analysis_enabled: code,
                                open_by_type: open,
                                declared_by_rules: declared.clone(),
                                open_by_category: by_category,
                                targets,
                            };
                        let (mut unsettled_sum, mut all_sum) = (HashMap::new(), HashMap::new());
                        let mut code_sum: HashMap<String, i64> = HashMap::new();
                        let mut per_target = Vec::new();
                        for (index, kind) in scope.iter().map(|index| &kinds[*index]).enumerate() {
                            let repository = matches!(kind.target, ScanTarget::Repository(_));
                            let unsettled: HashMap<FindingType, i64> = backlog
                                .iter()
                                .filter(|(type_, _)| repository || examinable(*type_, kind.target))
                                .copied()
                                .collect();
                            let mut all = unsettled.clone();
                            if index == 0 && repository {
                                *all.entry(FindingType::Secret).or_insert(0) += 1;
                            }
                            let code_open: HashMap<String, i64> = if repository && variant == 1 {
                                [("A03".to_owned(), 1)].into_iter().collect()
                            } else {
                                HashMap::new()
                            };
                            for (type_, count) in &unsettled {
                                *unsettled_sum.entry(*type_).or_insert(0) += count;
                            }
                            for (type_, count) in &all {
                                *all_sum.entry(*type_).or_insert(0) += count;
                            }
                            for (category, count) in &code_open {
                                *code_sum.entry(category.clone()).or_insert(0) += count;
                            }
                            let own =
                                assess_target(&measure(unsettled, code_open.clone(), vec![kind.clone()])).unwrap();
                            let own_all = assess_target(&measure(all, code_open, vec![kind.clone()])).unwrap();
                            per_target.push(split(&own, &own_all));
                        }
                        let targets: Vec<Evidence> = scope.iter().map(|index| kinds[*index].clone()).collect();
                        let scoped = split(
                            &assess(&measure(unsettled_sum, code_sum.clone(), targets.clone())),
                            &assess(&measure(all_sum, code_sum, targets)),
                        );
                        for line in scoped {
                            let lines: Vec<Split> = per_target
                                .iter()
                                .filter_map(|target| target.iter().find(|one| one.id == line.id).cloned())
                                .collect();
                            assert_eq!(
                                across_targets(&line.id, &lines),
                                Some(line.clone()),
                                "{scope:?} {variant} {code} {end_of_life}"
                            );
                            compared += 1;
                        }
                    }
                }
            }
        }
        assert!(compared > 1_000, "the scopes were all compared");
    }
}
