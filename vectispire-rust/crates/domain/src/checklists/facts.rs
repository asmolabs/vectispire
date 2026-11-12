//! `MeasurementFacts`: what the owners of the evidence answered about a project's repositories — the scans, the
//! plugins' outcomes, the imports, the backlog, the SBOMs, the forges' readings — as the rules read it.
//!
//! **Facts, not verdicts.** Whether a step is stale, absent or unrecorded is a rule's question; what an owner hands
//! over is what it recorded. A repository missing from a map is one the owner knows nothing of for that question,
//! which the rules read as "never examined", never as "examined, and clean" (decision 0007).

use std::collections::{BTreeMap, BTreeSet};

use crate::checklists::review::ChangeReviewEvidence;
use crate::instant::Instant;
use crate::java;
use crate::language::Language;

/// Where a piece of evidence was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    Scan,
    SarifImport,
    CoverageImport,
    TestReportImport,
    /// A reading of a forge's merge requests or pull requests, and of its branch settings (lot G3).
    ForgeReview,
}

impl Source {
    pub const ALL: [Source; 5] =
        [Source::Scan, Source::SarifImport, Source::CoverageImport, Source::TestReportImport, Source::ForgeReview];

    pub fn wire_name(self) -> &'static str {
        match self {
            Source::Scan => "scan",
            Source::SarifImport => "sarif_import",
            Source::CoverageImport => "coverage_import",
            Source::TestReportImport => "test_report_import",
            Source::ForgeReview => "forge_review",
        }
    }

    pub fn from_wire_name(value: &str) -> Option<Source> {
        Source::ALL.into_iter().find(|source| source.wire_name() == value)
    }
}

/// One scan or import a measurement rests on: what it was, when, and the digest of the document an import accepted
/// — which lets an auditor match the line with the report a pipeline sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Look {
    pub source: Source,
    pub id: i64,
    pub at: Instant,
    pub digest: Option<String>,
}

/// What an owner recorded about one scope on one repository.
#[derive(Debug, Clone)]
pub enum ScopeFacts {
    Scanned(Scanned),
    PluginRuns(PluginRuns),
    Imported(Imported),
}

/// A built-in step, as the scans recorded it.
#[derive(Debug, Clone)]
pub struct Scanned {
    /// The repository's newest completed scan, at any age, in which the step produced (`examined_types`).
    pub newest_producing: Option<Look>,
    /// Whether that scan stored an SBOM.
    pub sbom_stored: bool,
    /// Completed scans within the age that recorded which steps produced.
    pub recorded_within_age: i32,
    /// Completed scans within the age from before the record existed.
    pub unrecorded_within_age: i32,
}

/// A plugin's state in one scan: decision 0017's three, kept apart, and the executor's refusal by its reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginState {
    Produced,
    NotApplicable,
    Absent,
    /// Not started: no signer declared where one is required, and no waiver.
    RefusedUnsigned,
    /// Not started: the declared signer did not verify the image.
    RefusedSignatureUnverified,
    /// Not started: the registry would not let its signature be read.
    RefusedRegistryAuthenticationRequired,
}

/// One scan's run of a plugin.
#[derive(Debug, Clone)]
pub struct PluginRun {
    pub scan: Look,
    pub state: PluginState,
    /// The languages the manifest that scan named declared — never the plugin's current one; `None` when that
    /// manifest is not known.
    pub reads: Option<BTreeSet<Language>>,
}

/// A plugin, as the scans recorded it.
#[derive(Debug, Clone)]
pub struct PluginRuns {
    /// Its state in each completed scan within the age that names it.
    pub within_age: Vec<PluginRun>,
    /// Every completed scan within the age, naming it or not: one that does not name it ran without it.
    pub scans_within_age: i32,
    /// Whether a completed scan older than the age names it.
    pub named_before: bool,
}

/// An imported tool, as its declared source's imports recorded it.
#[derive(Debug, Clone)]
pub struct Imported {
    /// The newest import, at any age, whose accepted runs include the tool.
    pub newest_producing: Option<Look>,
    /// Whether an import from the source within the age predates the record of which tools an import carried.
    pub unrecorded_within_age: bool,
}

/// What one scan recorded of languages; `None` where it recorded none — unknown, never "counted, and none".
#[derive(Debug, Clone, Default)]
pub struct ScanLanguages {
    /// What its census found in the tree (`detected_languages`).
    pub detected: Option<BTreeSet<Language>>,
    /// What the Semgrep rules of its task read (`sast_languages`).
    pub sast_rules: Option<BTreeSet<Language>>,
}

/// Issues of one severity in one state, on one repository and one scope.
#[derive(Debug, Clone)]
pub struct IssueCount {
    pub severity: String,
    pub state: String,
    pub count: i64,
}

/// A repository's newest coverage import, at any age.
#[derive(Debug, Clone)]
pub struct CoverageReport {
    pub look: Look,
    pub lines_covered: i64,
    pub lines_total: i64,
    /// With `branches_total`: `None` when the report counted no branch.
    pub branches_covered: Option<i64>,
    pub branches_total: Option<i64>,
    /// Read only for a rule with a scope.
    pub packages: Packages,
}

/// What a coverage import kept of its packages, as the rules read it.
#[derive(Debug, Clone)]
pub enum Packages {
    /// Not asked: the rule has no scope. A scoped rule handed this is a defect, never a figure.
    NotRead,
    /// The import predates the record of packages (V71).
    Unrecorded,
    /// Not kept, for the import's own reason, in the words its evidence prints.
    NotKept(String),
    /// Every package the report counted something in, by path.
    Kept(Vec<PackageCounts>),
}

#[derive(Debug, Clone)]
pub struct PackageCounts {
    pub path: String,
    pub lines_covered: i64,
    pub lines_total: i64,
    pub branches_covered: Option<i64>,
    pub branches_total: Option<i64>,
}

/// A repository's newest test report, at any age.
#[derive(Debug, Clone)]
pub struct TestReport {
    pub look: Look,
    pub suites: Vec<Suite>,
}

#[derive(Debug, Clone)]
pub struct Suite {
    pub name: Option<String>,
    pub tests: i32,
    pub failures: i32,
    pub errors: i32,
    pub skipped: i32,
}

/// A component as the SBOM listed it; the version is the one the inventory stored.
#[derive(Debug, Clone)]
pub struct Component {
    pub name: Option<String>,
    pub version: Option<String>,
    pub purl: Option<String>,
}

/// The literal Syft writes where it could not tell a package's version — a Maven dependency whose version a parent or
/// a BOM it does not resolve manages; its purl then carries no version at all.
const SYFT_UNKNOWN: &str = "UNKNOWN";

impl Component {
    /// The version the SBOM states, or `None` where it states none — no version, a blank one, or Syft's `UNKNOWN`.
    /// Absent is not a version (decision 0007): read as one, a package present in the tree was judged "not an
    /// allowed version", and the automatic answer wrote "no" for a module that is there.
    pub fn stated_version(&self) -> Option<&str> {
        let version = self.version.as_deref()?;
        if java::is_blank(version)
            || java::compare_ignore_case(java::strip(version), SYFT_UNKNOWN) == std::cmp::Ordering::Equal
        {
            return None;
        }
        Some(version)
    }
}

/// What the forges recorded of one repository for the change-review rule.
#[derive(Debug, Clone)]
pub enum ReviewFacts {
    /// No forge connection imported the repository and no discovered repository has its URL: nothing to ask.
    Unlinked { look: Look, why: String },
    /// The forge would not answer about the project — the token refused, the project gone from its view.
    Unreadable { look: Look, why: String },
    /// The forge answered: its settings, its history, or both.
    Read { look: Look, evidence: ChangeReviewEvidence },
}

/// What the owners answered about a project's repositories, keyed by repository id (and by scope key where a rule
/// reads several scopes).
#[derive(Debug, Clone, Default)]
pub struct MeasurementFacts {
    /// The project's repositories, as the whole-project guard saw them.
    pub repository_ids: Vec<i64>,
    pub scopes: BTreeMap<String, BTreeMap<i64, ScopeFacts>>,
    /// Each repository's issues by severity and state, settled triage already left out by the owner's query.
    pub counts: BTreeMap<String, BTreeMap<i64, Vec<IssueCount>>>,
    /// For the dependency rule that asks it: whether each repository's schedule runs at least as often as its age.
    pub scheduled: BTreeMap<i64, bool>,
    pub coverage: BTreeMap<i64, CoverageReport>,
    pub tests: BTreeMap<i64, TestReport>,
    /// The components of each repository's newest scan in which the dependency step produced, at any age.
    pub components: BTreeMap<i64, Vec<Component>>,
    /// By scan id, what the scans a language-scoped analysis produced in recorded of languages.
    pub languages: BTreeMap<i64, ScanLanguages>,
    /// What the forges' readings recorded of each repository; one missing here was never read.
    pub reviews: BTreeMap<i64, ReviewFacts>,
}
