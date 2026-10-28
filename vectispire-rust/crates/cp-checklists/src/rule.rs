//! `ChecklistRule`: what a checklist line is measured by — a closed set of kinds, each with the parameters a person
//! binds on a draft version (decision 0032 §6).
//!
//! **Parameters, never a sentence**: a threshold is stated when the rule is bound, and nothing that decides an
//! outcome has a product default — what is not stated is refused, never assumed.
//!
//! **The canonical form is a data contract.** [`ChecklistRule::canonical`] is stored as the item's bound rule and
//! enters its content digest: keys sorted, no whitespace, ratios in their one decimal form, lists in a fixed order.
//! A change of this writing is a change of every bound item's digest, which marks every such line changed in the
//! next version. Held to Java's bytes in `reference/checklists/`.
//!
//! **The order of the refusals is Java's**: a constructor's arguments are read left to right before its body
//! checks them, so a rule with a bad scope and a bad age names the scope.

use std::collections::BTreeMap;

use vectispire_domain::Severity;
use vectispire_domain::bounded_text::clip;
use vectispire_domain::java;

use crate::allowed_component::{self as component, AllowedComponent};
use crate::coverage_scope::CoverageScope;
use crate::decimal::{self, Ratio};
use crate::node::{Node, Out};
use crate::tool_scope::ToolScope;
use crate::{Defect, Failure, Refused, refused, sha256_hex};

/// A year and a day: evidence older than that is no measurement of the state a release ships in.
pub const MAX_AGE_DAYS: i32 = 366;
pub const MAX_SCOPES: usize = 20;
pub const MAX_COMPONENTS: usize = 50;
pub const MAX_PATTERN: usize = 500;
pub const MAX_SUITE_PATTERNS: usize = 10;
pub const MAX_TESTS: i32 = 10_000_000;
pub const MAX_APPROVALS: i32 = 10;
pub const MAX_BRANCH: usize = 255;

/// The kinds, as the API and the stored form name them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    DependencyAnalysis,
    FindingsThreshold,
    CoverageThreshold,
    TestSuitePassed,
    ComponentVersions,
    ComponentPresent,
    ChangeReview,
}

impl Kind {
    pub const ALL: [Kind; 7] = [
        Kind::DependencyAnalysis,
        Kind::FindingsThreshold,
        Kind::CoverageThreshold,
        Kind::TestSuitePassed,
        Kind::ComponentVersions,
        Kind::ComponentPresent,
        Kind::ChangeReview,
    ];

    pub fn wire_name(self) -> &'static str {
        match self {
            Kind::DependencyAnalysis => "dependency_analysis",
            Kind::FindingsThreshold => "findings_threshold",
            Kind::CoverageThreshold => "coverage_threshold",
            Kind::TestSuitePassed => "test_suite_passed",
            Kind::ComponentVersions => "component_versions",
            Kind::ComponentPresent => "component_present",
            Kind::ChangeReview => "change_review",
        }
    }

    fn parse(value: Option<&str>) -> Result<Kind, Refused> {
        named(&Kind::ALL, Kind::wire_name, value, "kind")
    }

    /// The members a kind takes besides `kind` and `maxAgeDays`, as its refusal lists them (a `TreeSet`).
    fn allowed(self) -> &'static [&'static str] {
        match self {
            Kind::DependencyAnalysis => &["requireSchedule", "thresholds"],
            Kind::FindingsThreshold => &["scopes", "thresholds"],
            Kind::CoverageThreshold => &["aggregation", "metric", "minimumRatio", "scope"],
            Kind::TestSuitePassed => &["minimumTests", "suitePattern", "suitePatterns"],
            Kind::ComponentVersions | Kind::ComponentPresent => &["components"],
            Kind::ChangeReview => &["branch", "minimumApprovals", "minimumRatio", "windowDays"],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metric {
    Line,
    Branch,
}

impl Metric {
    pub const ALL: [Metric; 2] = [Metric::Line, Metric::Branch];

    pub fn wire_name(self) -> &'static str {
        match self {
            Metric::Line => "line",
            Metric::Branch => "branch",
        }
    }

    /// "lines" and "branches", in a measurement's sentences.
    pub fn plural(self) -> &'static str {
        match self {
            Metric::Line => "lines",
            Metric::Branch => "branches",
        }
    }
}

/// Per repository, each its own ratio; or the project's lines summed, weighted by their size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aggregation {
    PerRepository,
    ProjectWeighted,
}

impl Aggregation {
    pub const ALL: [Aggregation; 2] = [Aggregation::PerRepository, Aggregation::ProjectWeighted];

    pub fn wire_name(self) -> &'static str {
        match self {
            Aggregation::PerRepository => "per_repository",
            Aggregation::ProjectWeighted => "project_weighted",
        }
    }
}

/// What one severity may still hold for a findings rule to pass — the organisation's KPI: at most so many open
/// issues, at least such a share resolved; at least one of the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeverityThreshold {
    pub max_open: Option<i32>,
    pub min_resolved_ratio: Option<Ratio>,
}

/// A million: a KPI allowing more open issues than that is not a threshold.
pub const MAX_OPEN: i32 = 1_000_000;

impl SeverityThreshold {
    pub fn new(
        max_open: Option<i32>,
        min_resolved_ratio: Option<&decimal::Decimal>,
    ) -> Result<SeverityThreshold, Refused> {
        if max_open.is_none() && min_resolved_ratio.is_none() {
            return Err(refused("A severity's threshold states maxOpen, minResolvedRatio or both."));
        }
        if let Some(max) = max_open.filter(|max| !(0..=MAX_OPEN).contains(max)) {
            return Err(refused(format!("maxOpen is between 0 and {MAX_OPEN}; {max} is not.")));
        }
        let min_resolved_ratio =
            min_resolved_ratio.map(|ratio| Ratio::require(ratio, "minResolvedRatio", true)).transpose()?;
        Ok(SeverityThreshold { max_open, min_resolved_ratio })
    }
}

/// The thresholds by severity, in the enum's order (an `EnumMap`) — the order a measurement's figures are in.
pub type Thresholds = Vec<(Severity, SeverityThreshold)>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChecklistRule {
    /// The repository's dependencies analysed: its newest scan whose dependency step produced is within the age and
    /// stored an SBOM, the repository is — if asked — scheduled at least as often, and the vulnerabilities meet the
    /// thresholds, if any are stated.
    DependencyAnalysis { max_age_days: i32, require_schedule: bool, thresholds: Thresholds },
    /// Every scope produced within the age on every repository, and the backlog in those scopes meets the
    /// thresholds.
    FindingsThreshold { scopes: Vec<ToolScope>, max_age_days: i32, thresholds: Thresholds },
    /// The newest coverage import of each repository within the age, its ratio at least the minimum — over the whole
    /// report, or over the packages its scope names.
    CoverageThreshold {
        max_age_days: i32,
        metric: Metric,
        minimum_ratio: Ratio,
        aggregation: Aggregation,
        scope: Option<CoverageScope>,
    },
    /// The newest test report within the age, judged pattern by pattern; several patterns are all required.
    TestSuitePassed { max_age_days: i32, suite_patterns: Vec<String>, minimum_tests: i32 },
    /// Every declared package present, at an allowed version, in the SBOM of the newest analysed scan.
    ComponentVersions { max_age_days: i32, components: Vec<AllowedComponent> },
    /// Every declared package present, whatever its version.
    ComponentPresent { max_age_days: i32, purl_prefixes: Vec<String> },
    /// Every change merged into the branch reviewed by someone other than its author (decision 0037, lot G3).
    ChangeReview {
        max_age_days: i32,
        minimum_approvals: i32,
        window_days: i32,
        minimum_ratio: Ratio,
        branch: Option<String>,
    },
}

impl ChecklistRule {
    pub fn kind(&self) -> Kind {
        match self {
            ChecklistRule::DependencyAnalysis { .. } => Kind::DependencyAnalysis,
            ChecklistRule::FindingsThreshold { .. } => Kind::FindingsThreshold,
            ChecklistRule::CoverageThreshold { .. } => Kind::CoverageThreshold,
            ChecklistRule::TestSuitePassed { .. } => Kind::TestSuitePassed,
            ChecklistRule::ComponentVersions { .. } => Kind::ComponentVersions,
            ChecklistRule::ComponentPresent { .. } => Kind::ComponentPresent,
            ChecklistRule::ChangeReview { .. } => Kind::ChangeReview,
        }
    }

    /// How old the evidence may be — required of every kind.
    pub fn max_age_days(&self) -> i32 {
        match self {
            ChecklistRule::DependencyAnalysis { max_age_days, .. }
            | ChecklistRule::FindingsThreshold { max_age_days, .. }
            | ChecklistRule::CoverageThreshold { max_age_days, .. }
            | ChecklistRule::TestSuitePassed { max_age_days, .. }
            | ChecklistRule::ComponentVersions { max_age_days, .. }
            | ChecklistRule::ComponentPresent { max_age_days, .. }
            | ChecklistRule::ChangeReview { max_age_days, .. } => *max_age_days,
        }
    }

    // ------------------------------------------------------------------ reading

    /// A rule as a request states it, refused in words — a key another kind takes is refused, never ignored.
    pub fn parse(node: &Node) -> Result<ChecklistRule, Refused> {
        read(node, true)
    }

    /// A rule as a request states it, as JSON text.
    pub fn parse_text(json: Option<&str>) -> Result<ChecklistRule, Refused> {
        match read_tree(json.unwrap_or("")) {
            Ok(node) => ChecklistRule::parse(&node),
            Err(()) => Err(refused("A rule is a JSON object; this one does not read.")),
        }
    }

    /// A stored canonical form read back — written by [`canonical`](ChecklistRule::canonical), so a refusal is a
    /// defect; a check added after the rule was bound does not refuse it, since its text is its digest.
    pub fn from_canonical(canonical: &str) -> Result<ChecklistRule, Failure> {
        let node = read_tree(canonical).map_err(|()| Defect("A stored rule does not read as JSON.".to_owned()))?;
        Ok(read(&node, false)?)
    }

    // ------------------------------------------------------------------ the canonical form

    /// Keys sorted, no whitespace: the stored bound rule, and what the content digest reads.
    pub fn canonical(&self) -> String {
        let mut node: BTreeMap<&'static str, Out> = BTreeMap::new();
        node.insert("kind", Out::Text(self.kind().wire_name().to_owned()));
        node.insert("maxAgeDays", Out::Int(i64::from(self.max_age_days())));
        match self {
            ChecklistRule::DependencyAnalysis { require_schedule, thresholds, .. } => {
                node.insert("requireSchedule", Out::Bool(*require_schedule));
                if !thresholds.is_empty() {
                    node.insert("thresholds", thresholds_out(thresholds));
                }
            }
            ChecklistRule::FindingsThreshold { scopes, thresholds, .. } => {
                node.insert("scopes", Out::Array(scopes.iter().map(|scope| Out::Text(scope.key())).collect()));
                node.insert("thresholds", thresholds_out(thresholds));
            }
            ChecklistRule::CoverageThreshold { metric, minimum_ratio, aggregation, scope, .. } => {
                node.insert("metric", Out::Text(metric.wire_name().to_owned()));
                node.insert("minimumRatio", Out::Number(minimum_ratio.written()));
                node.insert("aggregation", Out::Text(aggregation.wire_name().to_owned()));
                // Only when present: a rule bound before scopes existed keeps its bytes, and its digest.
                if let Some(scope) = scope {
                    let mut written = BTreeMap::new();
                    if !scope.include.is_empty() {
                        written.insert("include", texts(&scope.include));
                    }
                    if !scope.exclude.is_empty() {
                        written.insert("exclude", texts(&scope.exclude));
                    }
                    node.insert("scope", Out::Object(written));
                }
            }
            ChecklistRule::TestSuitePassed { suite_patterns, minimum_tests, .. } => {
                // One pattern keeps the key it always had, so a rule bound before several existed keeps its bytes.
                match suite_patterns.as_slice() {
                    [one] => node.insert("suitePattern", Out::Text(one.clone())),
                    several => node.insert("suitePatterns", texts(several)),
                };
                node.insert("minimumTests", Out::Int(i64::from(*minimum_tests)));
            }
            ChecklistRule::ChangeReview { minimum_approvals, window_days, minimum_ratio, branch, .. } => {
                node.insert("minimumApprovals", Out::Int(i64::from(*minimum_approvals)));
                node.insert("windowDays", Out::Int(i64::from(*window_days)));
                node.insert("minimumRatio", Out::Number(minimum_ratio.written()));
                if let Some(branch) = branch {
                    node.insert("branch", Out::Text(branch.clone()));
                }
            }
            ChecklistRule::ComponentVersions { components, .. } => {
                let entries = components
                    .iter()
                    .map(|component| {
                        let mut entry = BTreeMap::new();
                        entry.insert("purlPrefix", Out::Text(component.purl_prefix.clone()));
                        entry.insert("versions", texts(&component.versions));
                        Out::Object(entry)
                    })
                    .collect();
                node.insert("components", Out::Array(entries));
            }
            ChecklistRule::ComponentPresent { purl_prefixes, .. } => {
                // The shape a component_versions entry has, its versions left out: one form for the API.
                let entries = purl_prefixes
                    .iter()
                    .map(|prefix| Out::Object(BTreeMap::from([("purlPrefix", Out::Text(prefix.clone()))])))
                    .collect();
                node.insert("components", Out::Array(entries));
            }
        }
        let mut out = String::new();
        Out::Object(node).write(&mut out);
        out
    }

    /// SHA-256 of the canonical form: what a measurement names as the rule it applied.
    pub fn digest(&self) -> String {
        sha256_hex(&self.canonical())
    }
}

fn texts(values: &[String]) -> Out {
    Out::Array(values.iter().map(|value| Out::Text(value.clone())).collect())
}

fn thresholds_out(thresholds: &Thresholds) -> Out {
    let mut node = BTreeMap::new();
    for (severity, threshold) in thresholds {
        let mut entry = BTreeMap::new();
        if let Some(max) = threshold.max_open {
            entry.insert("maxOpen", Out::Int(i64::from(max)));
        }
        if let Some(ratio) = threshold.min_resolved_ratio {
            entry.insert("minResolvedRatio", Out::Number(ratio.written()));
        }
        node.insert(severity.wire_name(), Out::Object(entry));
    }
    Out::Object(node)
}

/// `Json.READER.readTree`: the first value of the text (what follows is not read), `MissingNode` — read as `Null`,
/// which no rule is — for a text holding none, and `Err` for one that does not parse.
fn read_tree(text: &str) -> Result<Node, ()> {
    match serde_json::Deserializer::from_str(text).into_iter::<serde_json::Value>().next() {
        None => Ok(Node::Null),
        Some(Ok(value)) => Ok(Node::of(&value)),
        Some(Err(_)) => Err(()),
    }
}

/// `stated` is a person binding the rule now; otherwise it is a stored canonical form read back.
fn read(node: &Node, stated: bool) -> Result<ChecklistRule, Refused> {
    if !matches!(node, Node::Object(_)) {
        return Err(refused("A rule is an object: its kind, its maximum age and its parameters."));
    }
    let kind = Kind::parse(text(node, "kind")?.as_deref())?;
    let max_age = integer(node, "maxAgeDays")?.ok_or_else(|| {
        refused(
            "State the rule's maximum age, maxAgeDays — how old its evidence may be; a rule without one is refused.",
        )
    })?;
    if let Node::Object(members) = node {
        for (name, value) in members {
            if *value == Node::Null || name == "kind" || name == "maxAgeDays" {
                continue;
            }
            if !kind.allowed().contains(&name.as_str()) {
                return Err(refused(format!(
                    "A {} rule takes no \"{}\"; it takes {}.",
                    kind.wire_name(),
                    clip(Some(name), 40).unwrap_or(""),
                    kind.allowed().join(", ")
                )));
            }
        }
    }
    match kind {
        Kind::DependencyAnalysis => {
            let require_schedule = bool(node, "requireSchedule")?.ok_or_else(|| {
                refused("State whether the repository's schedule must match the maximum age, requireSchedule — true or false.")
            })?;
            let thresholds = thresholds(node.get("thresholds"))?;
            require_age(max_age)?;
            Ok(ChecklistRule::DependencyAnalysis { max_age_days: max_age, require_schedule, thresholds })
        }
        Kind::FindingsThreshold => {
            let mut scopes = scopes(node.get("scopes"))?;
            let thresholds = thresholds(node.get("thresholds"))?;
            require_age(max_age)?;
            if scopes.is_empty() || scopes.len() > MAX_SCOPES {
                return Err(refused(format!("A findings rule names 1 to {MAX_SCOPES} scopes.")));
            }
            let mut keys: Vec<String> = Vec::new();
            for scope in &scopes {
                let key = scope.key();
                if keys.contains(&key) {
                    return Err(refused(format!("The scope {key} is named twice.")));
                }
                keys.push(key);
            }
            scopes.sort_by(|left, right| java::compare_utf16(&left.key(), &right.key()));
            if thresholds.is_empty() {
                return Err(refused(
                    "A findings rule states a threshold for at least one severity — \"no plaintext secret\" is every \
                     count at zero.",
                ));
            }
            Ok(ChecklistRule::FindingsThreshold { scopes, max_age_days: max_age, thresholds })
        }
        Kind::CoverageThreshold => {
            let metric = named(&Metric::ALL, Metric::wire_name, text(node, "metric")?.as_deref(), "metric")?;
            let minimum_ratio = decimal(node, "minimumRatio")?
                .ok_or_else(|| refused("State the minimum coverage, minimumRatio — 0.8 for 80 %."))?;
            let aggregation =
                named(&Aggregation::ALL, Aggregation::wire_name, text(node, "aggregation")?.as_deref(), "aggregation")?;
            let scope = coverage_scope(node.get("scope"))?;
            require_age(max_age)?;
            let minimum_ratio = Ratio::require(&minimum_ratio, "minimumRatio", false)?;
            Ok(ChecklistRule::CoverageThreshold { max_age_days: max_age, metric, minimum_ratio, aggregation, scope })
        }
        Kind::TestSuitePassed => {
            let patterns = suite_patterns(node)?;
            let minimum_tests = integer(node, "minimumTests")?.ok_or_else(|| {
                refused("State the least number of tests the matching suites must run, minimumTests.")
            })?;
            require_age(max_age)?;
            if patterns.is_empty() || patterns.len() > MAX_SUITE_PATTERNS {
                return Err(refused(format!(
                    "A test rule names 1 to {MAX_SUITE_PATTERNS} suite patterns — *Test for unit tests, *IT for \
                     functional ones; each must be met."
                )));
            }
            let mut kept: Vec<String> = Vec::new();
            for given in &patterns {
                let pattern = java::strip(given.as_deref().unwrap_or(""));
                if pattern.is_empty()
                    || java::utf16_len(pattern) > MAX_PATTERN
                    || pattern.chars().any(java::is_iso_control)
                {
                    return Err(refused(format!(
                        "A suite pattern names the suites, 1 to {MAX_PATTERN} characters — com.example.arch.*, * for any \
                         run and ? for one character."
                    )));
                }
                kept.push(pattern.to_owned());
            }
            if !(1..=MAX_TESTS).contains(&minimum_tests) {
                return Err(refused("minimumTests is at least 1: a suite that ran nothing proves nothing."));
            }
            // Sorted and deduplicated: the same patterns are the same rule, whatever order a person typed.
            kept.sort_by(|left, right| java::compare_utf16(left, right));
            kept.dedup();
            Ok(ChecklistRule::TestSuitePassed { max_age_days: max_age, suite_patterns: kept, minimum_tests })
        }
        Kind::ComponentVersions => {
            let mut components = components(node.get("components"), stated)?;
            require_age(max_age)?;
            if components.is_empty() || components.len() > MAX_COMPONENTS {
                return Err(refused(format!("A component rule declares 1 to {MAX_COMPONENTS} packages.")));
            }
            let mut prefixes: Vec<&str> = Vec::new();
            for component in &components {
                if prefixes.contains(&component.purl_prefix.as_str()) {
                    return Err(refused(format!("The package {} is declared twice.", component.purl_prefix)));
                }
                prefixes.push(&component.purl_prefix);
            }
            components.sort_by(|left, right| java::compare_utf16(&left.purl_prefix, &right.purl_prefix));
            Ok(ChecklistRule::ComponentVersions { max_age_days: max_age, components })
        }
        Kind::ComponentPresent => {
            let given = present(node.get("components"), stated)?;
            require_age(max_age)?;
            if given.is_empty() || given.len() > MAX_COMPONENTS {
                return Err(refused(format!("A presence rule declares 1 to {MAX_COMPONENTS} packages.")));
            }
            let mut prefixes: Vec<String> = Vec::new();
            for prefix in &given {
                let kept = component::require_prefix(prefix)?;
                if prefixes.contains(&kept) {
                    return Err(refused(format!("The package {kept} is declared twice.")));
                }
                prefixes.push(kept);
            }
            prefixes.sort_by(|left, right| java::compare_utf16(left, right));
            Ok(ChecklistRule::ComponentPresent { max_age_days: max_age, purl_prefixes: prefixes })
        }
        Kind::ChangeReview => {
            let minimum_approvals = integer(node, "minimumApprovals")?.ok_or_else(|| {
                refused("State how many people other than the author must approve a change, minimumApprovals — 1 for a peer.")
            })?;
            let window_days = integer(node, "windowDays")?.ok_or_else(|| {
                refused("State how far back the merged changes are counted, windowDays — 30 for the last month.")
            })?;
            let minimum_ratio = decimal(node, "minimumRatio")?.ok_or_else(|| {
                refused(
                    "State the share of merged changes that must have been approved, minimumRatio — 1 for every one.",
                )
            })?;
            let branch = text(node, "branch")?;
            require_age(max_age)?;
            if !(1..=MAX_APPROVALS).contains(&minimum_approvals) {
                return Err(refused(format!(
                    "minimumApprovals is 1 to {MAX_APPROVALS} — a review by nobody is no review; {minimum_approvals} is \
                     not."
                )));
            }
            if !(1..=MAX_AGE_DAYS).contains(&window_days) {
                return Err(refused(format!("windowDays is between 1 and {MAX_AGE_DAYS}; {window_days} is not.")));
            }
            let minimum_ratio = Ratio::require(&minimum_ratio, "minimumRatio", false)?;
            let branch = branch.as_deref().map(branch_name).transpose()?;
            Ok(ChecklistRule::ChangeReview {
                max_age_days: max_age,
                minimum_approvals,
                window_days,
                minimum_ratio,
                branch,
            })
        }
    }
}

fn require_age(max_age_days: i32) -> Result<(), Refused> {
    if !(1..=MAX_AGE_DAYS).contains(&max_age_days) {
        return Err(refused(format!("maxAgeDays is between 1 and {MAX_AGE_DAYS}; {max_age_days} is not.")));
    }
    Ok(())
}

/// A branch as a rule names it: what Git accepts in a ref's last part and a forge's API in a path.
fn branch_name(value: &str) -> Result<String, Refused> {
    let branch = java::strip(value);
    if branch.is_empty()
        || java::utf16_len(branch) > MAX_BRANCH
        || branch.contains("..")
        || branch.chars().any(|c| java::is_iso_control(c) || java::is_whitespace(c) || "~^:?*[\\".contains(c))
    {
        return Err(refused(format!(
            "branch names one branch, 1 to {MAX_BRANCH} characters as Git writes it — main, release/2026; leave it out \
             for the default branch."
        )));
    }
    Ok(branch.to_owned())
}

fn thresholds(node: Option<&Node>) -> Result<Thresholds, Refused> {
    let mut thresholds: Thresholds = Vec::new();
    let members = match node {
        None | Some(Node::Null) => return Ok(thresholds),
        Some(Node::Object(members)) => members,
        Some(_) => return Err(refused("thresholds is an object: each severity, and what it may hold.")),
    };
    for (name, threshold) in members {
        let severity = named(&SEVERITIES, Severity::wire_name, Some(name), "severity")?;
        let Node::Object(fields) = threshold else {
            return Err(refused(format!(
                "The {} threshold is an object — maxOpen, minResolvedRatio.",
                severity.wire_name()
            )));
        };
        for (field, value) in fields {
            if field != "maxOpen" && field != "minResolvedRatio" && *value != Node::Null {
                return Err(refused(format!(
                    "A severity's threshold takes maxOpen and minResolvedRatio; \"{}\" is neither.",
                    clip(Some(field), 40).unwrap_or("")
                )));
            }
        }
        let max_open = integer(threshold, "maxOpen")?;
        let ratio = decimal(threshold, "minResolvedRatio")?;
        let parsed = SeverityThreshold::new(max_open, ratio.as_ref())?;
        // An `EnumMap`'s put: the last one for a severity wins, in the severity's place.
        match thresholds.iter_mut().find(|(known, _)| *known == severity) {
            Some(slot) => slot.1 = parsed,
            None => thresholds.push((severity, parsed)),
        }
    }
    thresholds.sort_by_key(|(severity, _)| *severity);
    Ok(thresholds)
}

const SEVERITIES: [Severity; 6] =
    [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Negligible, Severity::Unknown];

fn scopes(node: Option<&Node>) -> Result<Vec<ToolScope>, Refused> {
    let Some(Node::Array(items)) = node else {
        return Err(refused("A findings rule names its scopes — builtin:sast, plugin:<id>, import:<source>/<tool>."));
    };
    items
        .iter()
        .map(|scope| match scope {
            Node::Text(text) => ToolScope::parse(Some(text)),
            _ => Err(refused("A scope is a string, builtin:<step>, plugin:<id> or import:<source>/<tool>.")),
        })
        .collect()
}

/// `{"include": [...], "exclude": [...]}`, either list optional; absent or null is no scope.
fn coverage_scope(node: Option<&Node>) -> Result<Option<CoverageScope>, Refused> {
    let members = match node {
        None | Some(Node::Null) => return Ok(None),
        Some(Node::Object(members)) => members,
        Some(_) => {
            return Err(refused(
                "scope is an object — include and exclude, each a list of patterns over package paths, **/service/**.",
            ));
        }
    };
    for (name, value) in members {
        if name != "include" && name != "exclude" && *value != Node::Null {
            return Err(refused(format!(
                "A coverage scope takes include and exclude; \"{}\" is neither.",
                clip(Some(name), 40).unwrap_or("")
            )));
        }
    }
    let scope = node.unwrap_or(&Node::Null);
    let include = pattern_list(scope.get("include"), "include")?;
    let exclude = pattern_list(scope.get("exclude"), "exclude")?;
    CoverageScope::new(Some(&include), Some(&exclude)).map(Some)
}

/// `suitePattern` for one, `suitePatterns` for several — one of the two, never both.
fn suite_patterns(node: &Node) -> Result<Vec<Option<String>>, Refused> {
    let one = node.get("suitePattern");
    let several = node.get("suitePatterns");
    if !Node::is_null(one) && !Node::is_null(several) {
        return Err(refused(
            "A test rule names its suites once: suitePattern for one pattern, or suitePatterns for several — not both.",
        ));
    }
    let Some(several) = several.filter(|several| **several != Node::Null) else {
        return Ok(vec![text(node, "suitePattern")?]);
    };
    let Node::Array(items) = several else {
        return Err(refused("suitePatterns is a list of patterns — [\"*Test\", \"*IT\"]."));
    };
    items
        .iter()
        .map(|pattern| match pattern {
            Node::Text(text) => Ok(Some(text.clone())),
            _ => Err(refused("A suite pattern is a string — *Test, com.example.arch.*.")),
        })
        .collect()
}

fn pattern_list(node: Option<&Node>, what: &str) -> Result<Vec<Option<String>>, Refused> {
    let items = match node {
        None | Some(Node::Null) => return Ok(Vec::new()),
        Some(Node::Array(items)) => items,
        Some(_) => return Err(refused(format!("The coverage scope's {what} is a list of patterns."))),
    };
    items
        .iter()
        .map(|pattern| match pattern {
            Node::Text(text) => Ok(Some(text.clone())),
            _ => Err(refused(format!("A pattern in the coverage scope's {what} is a string."))),
        })
        .collect()
}

fn components(node: Option<&Node>, stated: bool) -> Result<Vec<AllowedComponent>, Refused> {
    let Some(Node::Array(items)) = node else {
        return Err(refused(
            "A component rule declares its packages, components: each a purlPrefix and its allowed versions.",
        ));
    };
    let mut components = Vec::new();
    for component in items {
        if !matches!(component, Node::Object(_)) {
            return Err(refused("A declared package is an object, purlPrefix and versions."));
        }
        let Some(Node::Array(versions)) = component.get("versions") else {
            return Err(refused("A declared package lists its allowed versions, versions."));
        };
        let mut allowed = Vec::new();
        for version in versions {
            let Node::Text(version) = version else {
                return Err(refused("An allowed version is a string, as the SBOM writes it."));
            };
            allowed.push(version.clone());
        }
        let prefix = text(component, "purlPrefix")?.unwrap_or_default();
        components.push(if stated {
            AllowedComponent::declared(&prefix, &allowed)?
        } else {
            AllowedComponent::new(&prefix, &allowed)?
        });
    }
    Ok(components)
}

fn present(node: Option<&Node>, stated: bool) -> Result<Vec<String>, Refused> {
    let Some(Node::Array(items)) = node else {
        return Err(refused("A presence rule declares its packages, components: each a purlPrefix."));
    };
    let mut prefixes = Vec::new();
    for component in items {
        let Node::Object(fields) = component else {
            return Err(refused("A declared package is an object, its purlPrefix."));
        };
        for (field, value) in fields {
            if field == "purlPrefix" || *value == Node::Null {
                continue;
            }
            return Err(if field == "versions" {
                refused(format!(
                    "A component_present rule asks for a package whatever its version, and {} lists versions — bind \
                     component_versions to judge them.",
                    clip(Some(&text(component, "purlPrefix")?.unwrap_or_default()), 60).unwrap_or("")
                ))
            } else {
                refused(format!(
                    "A declared package takes a purlPrefix; \"{}\" is not one.",
                    clip(Some(field), 40).unwrap_or("")
                ))
            });
        }
        let prefix = component::require_prefix(&text(component, "purlPrefix")?.unwrap_or_default())?;
        if stated {
            component::refuse_ending_on_separator(&prefix)?;
        }
        prefixes.push(prefix);
    }
    Ok(prefixes)
}

/// One of a closed set as a rule names it, refused listing the set.
fn named<E: Copy>(
    values: &[E],
    wire_name: fn(E) -> &'static str,
    value: Option<&str>,
    what: &str,
) -> Result<E, Refused> {
    let wanted = java::to_lower_root(java::strip(value.unwrap_or("")));
    values.iter().copied().find(|candidate| wire_name(*candidate) == wanted).ok_or_else(|| {
        let names: Vec<&str> = values.iter().map(|candidate| wire_name(*candidate)).collect();
        refused(format!(
            "A rule's {what} is one of {}{}",
            names.join(", "),
            if wanted.is_empty() {
                "; none was given.".to_owned()
            } else {
                format!("; \"{}\" is not one.", clip(Some(&wanted), 40).unwrap_or(""))
            }
        ))
    })
}

fn text(node: &Node, name: &str) -> Result<Option<String>, Refused> {
    match node.get(name) {
        None | Some(Node::Null) => Ok(None),
        Some(Node::Text(text)) => Ok(Some(text.clone())),
        Some(_) => Err(refused(format!("{name} is a string."))),
    }
}

fn integer(node: &Node, name: &str) -> Result<Option<i32>, Refused> {
    match node.get(name) {
        None | Some(Node::Null) => Ok(None),
        Some(value) => value.int().map(Some).ok_or_else(|| refused(format!("{name} is a whole number."))),
    }
}

fn bool(node: &Node, name: &str) -> Result<Option<bool>, Refused> {
    match node.get(name) {
        None | Some(Node::Null) => Ok(None),
        Some(Node::Bool(flag)) => Ok(Some(*flag)),
        Some(_) => Err(refused(format!("{name} is true or false."))),
    }
}

fn decimal(node: &Node, name: &str) -> Result<Option<decimal::Decimal>, Refused> {
    match node.get(name) {
        None | Some(Node::Null) => Ok(None),
        Some(value) => value.decimal().map(Some).ok_or_else(|| refused(format!("{name} is a number — 0.6 for 60 %."))),
    }
}
