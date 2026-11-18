//! The pure compliance domain against Java's answers in `reference/compliance/`, written by
//! `ComplianceReferenceSetTest`: the frameworks and their identifiers, the engine over a grid of estates and
//! platforms, the declaration of applicability, the history, the scope and the manifest, the OWASP grid over every
//! scope of the kinds of evidence, the CWE lists, the coverage week, the MTTR and the spreadsheet cells.
//!
//! **Exactly**: where Java wrote a record whole, the Rust record is serialized and compared as text, so a field's
//! name, its place and a null are compared with its value.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeSet, HashMap};

use serde_json::Value;
use vectispire_cp_compliance::decisions::{
    self, ComplianceEvaluation, ComplianceFramework, ComplianceSnapshot, ControlAssessment, Declaration,
    EvidenceBundleManifest, PasswordAccounts, PlatformPosture, PostureInput, ScopeCoverage, Status,
};
use vectispire_domain::FindingType;
use vectispire_domain::instant::Instant;
use vectispire_domain::language::Language;
use vectispire_domain::observation::Observation;
use vectispire_domain::owasp_coverage::{self, CoverageReason, Evidence, Measurement, Split};
use vectispire_domain::scan_target::ScanTarget;
use vectispire_domain::{mttr, owasp_cwe, spreadsheet_cells};

fn read(name: &str) -> Value {
    vectispire_testkit::read_json(&format!("compliance/{name}"))
}

/// Compact text, keys in the order Java wrote them (`preserve_order`).
fn text<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap()
}

fn str_of(value: &Value) -> &str {
    value.as_str().unwrap()
}

fn strings(value: &Value) -> Option<Vec<String>> {
    value.as_array().map(|items| items.iter().map(|item| str_of(item).to_owned()).collect())
}

fn framework(name: &str) -> ComplianceFramework {
    ComplianceFramework::from_name(name).unwrap()
}

#[test]
fn the_frameworks_and_how_a_segment_names_one() {
    let set = read("frameworks.json");
    let frameworks = set["frameworks"].as_array().unwrap();
    assert_eq!(frameworks.len(), ComplianceFramework::ALL.len());
    for (row, framework) in frameworks.iter().zip(ComplianceFramework::ALL) {
        assert_eq!(str_of(&row["name"]), framework.name());
        assert_eq!(str_of(&row["title"]), framework.title());
        assert_eq!(str_of(&row["description"]), framework.description());
        assert_eq!(text(&framework.controls()), text(&row["controls"]), "{}", framework.name());
    }
    for row in set["identifiers"].as_array().unwrap() {
        let input = str_of(&row["input"]);
        match ComplianceFramework::from_identifier(input) {
            Ok(found) => assert_eq!(Some(found.name()), row["framework"].as_str(), "{input:?}"),
            Err(refused) => assert_eq!(Some(refused.to_string().as_str()), row["refused"].as_str(), "{input:?}"),
        }
    }
}

fn input(row: &Value) -> PostureInput {
    let values = row.as_array().unwrap();
    let int = |index: usize| i32::try_from(values[index].as_i64().unwrap()).unwrap();
    let long = |index: usize| values[index].as_i64().unwrap();
    PostureInput {
        total_targets: int(0),
        scanned_targets: int(1),
        freshly_scanned_targets: int(2),
        freshness_window_days: int(3),
        gate_passing_targets: int(4),
        critical_issues: long(5),
        high_issues: long(6),
        medium_issues: long(7),
        low_issues: long(8),
        kev_issues: long(9),
        overdue_issues: long(10),
        secret_issues: long(11),
        sast_issues: long(12),
        iac_issues: long(13),
        targets_with_sbom: int(14),
        audit_chain_valid: values[15].as_bool().unwrap(),
    }
}

fn platform(row: &Value) -> PlatformPosture {
    let values: Vec<i64> = row.as_array().unwrap().iter().map(|value| value.as_i64().unwrap()).collect();
    PlatformPosture {
        encryption_configured: values[0] == 1,
        external_kms: values[1] == 1,
        audit_mirror_configured: values[2] == 1,
        four_eyes_required: values[3] == 1,
        single_sign_on_configured: values[4] == 1,
        password_login_open: values[5] == 1,
        password_accounts: PasswordAccounts { accounts: values[6], without_second_factor: values[7] },
    }
}

#[test]
fn the_engine_over_every_estate_and_platform() {
    let set = read("engine.json");
    let texts: Vec<&str> = set["texts"].as_array().unwrap().iter().map(str_of).collect();
    let rows = set["rows"].as_array().unwrap();
    assert!(rows.len() > 150, "the grid was read");
    for row in rows {
        let estate = input(&row["input"]);
        let evaluations = decisions::evaluate_all(&estate, &platform(&row["platform"]));
        let frameworks: Vec<String> = evaluations
            .iter()
            .map(|evaluation| {
                format!(
                    "{} {} {}",
                    evaluation.framework.name(),
                    evaluation.score_percentage,
                    evaluation.overall_status.name()
                )
            })
            .collect();
        assert_eq!(Some(frameworks), strings(&row["frameworks"]), "{}", row["input"]);
        let categories = row["categories"].as_object().unwrap();
        let mut seen = BTreeSet::new();
        for control in evaluations.iter().flat_map(|evaluation| &evaluation.controls) {
            let expected: Vec<&str> = str_of(&categories[control.control.category.name()]).split(' ').collect();
            let resolved = format!(
                "{} {} {} | {}",
                expected[0],
                expected[1],
                texts[expected[2].parse::<usize>().unwrap()],
                texts[expected[3].parse::<usize>().unwrap()]
            );
            let actual = format!(
                "{} {} {} | {}",
                control.status.name(),
                control.score_percentage,
                control.details,
                control.remediation_guidance
            );
            assert_eq!(actual, resolved, "{} over {} {}", control.control.id, row["input"], row["platform"]);
            seen.insert(control.control.category.name());
        }
        assert_eq!(seen.len(), categories.len(), "every category Java assessed is assessed here");
    }
    for row in set["shapes"].as_array().unwrap() {
        let evaluation = decisions::evaluate(
            ComplianceFramework::Soc2,
            &input(&row["input"]),
            &platform(&serde_json::json!([1, 1, 1, 1, 0, 1, 3, 1])),
        );
        assert_eq!(text(&evaluation), text(&row["evaluation"]));
    }
}

fn now(set: &Value) -> Instant {
    Instant::parse_java(str_of(&set["now"])).unwrap()
}

fn status(name: &str) -> Option<Status> {
    serde_json::from_value(Value::String(name.to_owned())).ok()
}

/// An evaluation of these statuses, the only part of one the reconciliation reads.
fn evaluation_of(framework: ComplianceFramework, measured: &[(String, Status)]) -> ComplianceEvaluation {
    let controls = measured
        .iter()
        .map(|(id, status)| ControlAssessment {
            control: framework.controls().iter().find(|control| control.id == id).unwrap(),
            status: *status,
            score_percentage: 0,
            details: String::new(),
            remediation_guidance: String::new(),
        })
        .collect();
    ComplianceEvaluation { framework, score_percentage: 0, overall_status: Status::NoData, controls }
}

#[test]
fn the_declaration_of_applicability() {
    let set = read("soa.json");
    let now = now(&set);
    let divergences = set["divergences"].as_array().unwrap();
    assert_eq!(divergences.len(), 2 * 4 * 5 * 3 * 5);
    for row in divergences {
        let fields: Vec<&str> = str_of(row).split('|').collect();
        let declaration = Declaration {
            framework: "ISO_27001".to_owned(),
            control_id: "ISO-A.8.8".to_owned(),
            applicability: serde_json::from_value(Value::String(fields[0].to_owned())).ok(),
            justification: (fields[1] != "null").then(|| fields[1].to_owned()),
            implementation: serde_json::from_value(Value::String(fields[2].to_owned())).ok(),
            evidence_source: serde_json::from_value(Value::String(fields[3].to_owned())).ok(),
            external_evidence: None,
            owner: None,
            decided_by: None,
            decided_at: None,
            reviewed_at: None,
            review_due_at: None,
        };
        let measured: Vec<(String, Status)> =
            status(fields[4]).map(|status| ("ISO-A.8.8".to_owned(), status)).into_iter().collect();
        let statement =
            decisions::reconcile(&evaluation_of(ComplianceFramework::Iso27001, &measured), &[declaration], now);
        assert_eq!(text(&statement.lines[0].divergence), format!("\"{}\"", fields[5]), "{}", str_of(row));
    }
    for row in set["statements"].as_array().unwrap() {
        let framework = framework(str_of(&row["framework"]));
        let measured: Vec<(String, Status)> = row["measured"]
            .as_array()
            .unwrap()
            .iter()
            .map(|line| {
                let (id, name) = str_of(line).split_once(' ').unwrap();
                (id.to_owned(), status(name).unwrap())
            })
            .collect();
        let declarations: Vec<Declaration> = serde_json::from_value(row["declarations"].clone()).unwrap();
        assert_eq!(text(&declarations), text(&row["declarations"]), "a declaration reads back as Java wrote it");
        let statement = decisions::reconcile(&evaluation_of(framework, &measured), &declarations, now);
        assert_eq!(text(&statement), text(&row["statement"]));
    }
}

#[test]
fn the_history_attributes_each_month() {
    let set = read("history.json");
    for row in set["series"].as_array().unwrap() {
        let snapshots: Vec<ComplianceSnapshot> = serde_json::from_value(row["snapshots"].clone()).unwrap();
        assert_eq!(text(&snapshots), text(&row["snapshots"]));
        let series = decisions::history::of(framework(str_of(&row["framework"])), &snapshots);
        assert_eq!(text(&series), text(&row["series"]));
    }
}

#[test]
fn the_scope_and_the_manifest() {
    let set = read("records.json");
    for row in set["scope"].as_array().unwrap() {
        let coverage: ScopeCoverage = serde_json::from_value(row["coverage"].clone()).unwrap();
        assert_eq!(text(&coverage), text(&row["coverage"]));
        assert_eq!(i64::from(coverage.unaccounted_for()), row["unaccountedFor"].as_i64().unwrap());
        assert_eq!(coverage.declared(), row["declared"].as_bool().unwrap());
    }
    for manifest in set["manifests"].as_array().unwrap() {
        let read: EvidenceBundleManifest = serde_json::from_value(manifest.clone()).unwrap();
        assert_eq!(text(&read), text(manifest));
    }
}

fn evidence(kind: &Value) -> Evidence {
    let (kind_name, id) = str_of(&kind["target"]).split_once(':').unwrap();
    let id: i64 = id.parse().unwrap();
    let target = if kind_name == "repo" { ScanTarget::Repository(id) } else { ScanTarget::Container(id) };
    Evidence::new(
        target,
        observation(str_of(&kind["observation"])),
        types(&kind["examined"]),
        languages(&kind["analysed"]),
        strings(&kind["codeReaches"]).map(|found| found.into_iter().collect()),
    )
}

fn observation(name: &str) -> Observation {
    match name {
        "OK" => Observation::Ok,
        "NEVER_SCANNED" => Observation::NeverScanned,
        "LAST_SCAN_FAILED" => Observation::LastScanFailed,
        "IN_PROGRESS" => Observation::InProgress,
        other => panic!("{other}"),
    }
}

fn finding_type(wire: &str) -> FindingType {
    FindingType::ALL.into_iter().find(|type_| type_.wire_name() == wire).unwrap()
}

fn types(value: &Value) -> Option<BTreeSet<FindingType>> {
    strings(value).map(|found| found.iter().map(|wire| finding_type(wire)).collect())
}

fn languages(value: &Value) -> Option<BTreeSet<Language>> {
    strings(value).map(|found| found.iter().map(|wire| Language::from_wire_name(wire).unwrap()).collect())
}

fn measurement(spec: &Value, kinds: &[Evidence], open: &str, by_category: &str) -> Measurement {
    Measurement {
        end_of_life_enabled: spec["endOfLife"].as_bool().unwrap(),
        code_analysis_enabled: spec["code"].as_bool().unwrap(),
        open_by_type: spec[open]
            .as_object()
            .unwrap()
            .iter()
            .map(|(wire, count)| (finding_type(wire), count.as_i64().unwrap()))
            .collect(),
        declared_by_rules: strings(&spec["declared"]).unwrap().into_iter().collect(),
        open_by_category: spec[by_category]
            .as_object()
            .unwrap()
            .iter()
            .map(|(category, count)| (category.clone(), count.as_i64().unwrap()))
            .collect(),
        targets: spec["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|index| kinds[usize::try_from(index.as_u64().unwrap()).unwrap()].clone())
            .collect(),
    }
}

fn reason_text(reason: &CoverageReason) -> String {
    let mut written = serde_json::to_value(reason).unwrap();
    written.as_object_mut().unwrap().insert("sentence".to_owned(), Value::String(reason.sentence()));
    text(&written)
}

fn check_grid(grid: &owasp_coverage::Grid, splits: &[Split], expected: &Value, reasons: &[Value], what: &str) {
    assert_eq!(i64::from(grid.covered), expected["covered"].as_i64().unwrap(), "{what}");
    assert_eq!(i64::from(grid.with_findings), expected["withFindings"].as_i64().unwrap(), "{what}");
    assert_eq!(i64::from(grid.unmeasured), expected["unmeasured"].as_i64().unwrap(), "{what}");
    let lines = expected["lines"].as_array().unwrap();
    assert_eq!(grid.lines.len(), lines.len());
    for ((line, split), expected) in grid.lines.iter().zip(splits).zip(lines) {
        let fields: Vec<&str> = str_of(expected).split(' ').collect();
        let actual = format!("{} {} {} {}", line.id, text(&line.state).trim_matches('"'), line.findings, split.settled);
        assert_eq!(actual, fields[..4].join(" "), "{what}");
        assert_eq!(line.because, line.reason.sentence());
        let reason = &reasons[fields[4].parse::<usize>().unwrap()];
        assert_eq!(reason_text(&line.reason), text(reason), "{what} {}", line.id);
        assert_eq!(split.id, line.id);
        assert_eq!((split.state, split.open), (line.state, line.findings));
    }
}

#[test]
fn the_owasp_grid_over_every_scope() {
    let set = read("owasp.json");
    let categories: Vec<(String, String)> = set["categories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| (str_of(&pair[0]).to_owned(), str_of(&pair[1]).to_owned()))
        .collect();
    let ours: Vec<(String, String)> =
        owasp_coverage::CATEGORIES.iter().map(|(id, title)| ((*id).to_owned(), (*title).to_owned())).collect();
    assert_eq!(ours, categories);
    let kinds: Vec<Evidence> = set["kinds"].as_array().unwrap().iter().map(evidence).collect();
    let reasons = set["reasons"].as_array().unwrap();
    let measurements = set["measurements"].as_array().unwrap();
    assert_eq!(measurements.len(), 586, "every scope of the fold and the chosen cases");
    for spec in measurements {
        let what = format!("{} {} {} {}", spec["targets"], spec["endOfLife"], spec["code"], spec["open"]);
        let unsettled = measurement(spec, &kinds, "open", "byCategory");
        let all = measurement(spec, &kinds, "openAll", "byCategoryAll");
        let grid = owasp_coverage::assess(&unsettled);
        let splits = owasp_coverage::split(&grid, &owasp_coverage::assess(&all));
        check_grid(&grid, &splits, &spec["grid"], reasons, &what);
        match owasp_coverage::assess_target(&unsettled) {
            Ok(own) => {
                let splits = owasp_coverage::split(&own, &owasp_coverage::assess_target(&all).unwrap());
                check_grid(&own, &splits, &spec["target"], reasons, &format!("own {what}"));
            }
            Err(_) => assert!(spec.get("target").is_none(), "{what}"),
        }
    }
    for (scope, refusal) in [vec![], vec![0, 1]].iter().zip(set["assessTargetRefusals"].as_array().unwrap()) {
        let measurement = Measurement {
            targets: scope.iter().map(|index: &usize| kinds[*index].clone()).collect(),
            ..Measurement::default()
        };
        let refused = owasp_coverage::assess_target(&measurement).unwrap_err().to_string();
        assert_eq!(Some(refused.as_str()), refusal.as_str());
    }
    for row in set["acrossTargets"].as_array().unwrap() {
        let lines: Vec<Split> = serde_json::from_value(row["lines"].clone()).unwrap();
        let folded = owasp_coverage::across_targets(str_of(&row["id"]), &lines);
        assert_eq!(text(&folded), text(&row["fold"]), "{}", row["lines"]);
    }
    for row in set["sentences"].as_array().unwrap() {
        let reason: CoverageReason = serde_json::from_value(row.clone()).unwrap();
        assert_eq!(reason.sentence(), str_of(&row["sentence"]));
    }
}

#[test]
fn the_placement_of_one_issue() {
    let set = read("owasp.json");
    let placement = &set["placement"];
    for row in placement["placementOf"].as_array().unwrap() {
        let fields: Vec<&str> = str_of(row).split('|').collect();
        let declared = (fields[1] != "null").then_some(fields[1]);
        let placed = owasp_coverage::placement_of(finding_type(fields[0]), declared);
        assert_eq!(placed.unwrap_or("null"), fields[2], "{}", str_of(row));
    }
    for row in placement["examinable"].as_array().unwrap() {
        let fields: Vec<&str> = str_of(row).split('|').collect();
        let type_ = finding_type(fields[0]);
        assert_eq!(owasp_coverage::examinable(type_, ScanTarget::Repository(1)).to_string(), fields[1]);
        assert_eq!(owasp_coverage::examinable(type_, ScanTarget::Container(1)).to_string(), fields[2]);
    }
    for row in placement["typesPlacedIn"].as_array().unwrap() {
        let (category, types) = str_of(row).split_once('|').unwrap();
        assert_eq!(owasp_coverage::types_placed_in(category).join(","), types);
    }
    assert_eq!(owasp_coverage::types_placed_anywhere().join(","), str_of(&placement["typesPlacedAnywhere"]));
    for row in placement["unplacedCode"].as_array().unwrap() {
        let by_category: HashMap<String, i64> = serde_json::from_value(row["byCategory"].clone()).unwrap();
        let unplaced = owasp_coverage::unplaced_code(
            row["openCode"].as_i64().unwrap(),
            by_category.iter().map(|(category, count)| (category.as_str(), *count)),
        );
        assert_eq!(unplaced, row["unplaced"].as_i64().unwrap());
    }
    let declared: HashMap<Language, BTreeSet<String>> =
        [("python", vec!["A03"]), ("java", vec!["A02", "A05"]), ("go", vec![])]
            .into_iter()
            .map(|(language, categories)| {
                (Language::from_wire_name(language).unwrap(), categories.into_iter().map(str::to_owned).collect())
            })
            .collect();
    for row in placement["evidenceOf"].as_array().unwrap() {
        let of = Evidence::of(
            ScanTarget::Repository(1),
            observation(str_of(&row["observation"])),
            types(&row["examined"]),
            languages(&row["detected"]).as_ref(),
            languages(&row["sastRules"]).as_ref(),
            &declared,
        );
        let examined = of.examined().map(|types| types.iter().map(|type_| type_.wire_name().to_owned()).collect());
        let analysed =
            of.analysed().map(|found| found.iter().map(|language| language.wire_name().to_owned()).collect());
        let reaches: Option<Vec<String>> = of.code_reaches().map(|found| found.iter().cloned().collect());
        assert_eq!(examined, strings(&row["examinedAfter"]), "{row}");
        assert_eq!(analysed, strings(&row["analysed"]), "{row}");
        assert_eq!(reaches, strings(&row["codeReaches"]), "{row}");
    }
}

/// The one declaration Java reads differently, on purpose here: a combining mark right after the number is part of
/// the word to `java.util.regex`'s `\b`, and the ASCII boundary does not know it (`owasp_cwe`'s module note).
const COMBINING_MARK: &str = "CWE-89\u{301}";

#[test]
fn the_cwe_lists_and_the_declarations() {
    let set = read("cwe.json");
    let table: Vec<(i64, String)> = set["table"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| (pair[0].as_i64().unwrap(), str_of(&pair[1]).to_owned()))
        .collect();
    let ours: Vec<(i64, String)> = (0..=2_000)
        .filter_map(|cwe: i32| owasp_cwe::category_of(cwe).map(|category| (i64::from(cwe), category.to_owned())))
        .collect();
    assert_eq!(ours, table);
    for pair in set["declarations"].as_array().unwrap() {
        let declaration = str_of(&pair[0]);
        let category = owasp_cwe::category_of_declaration(declaration);
        if declaration == COMBINING_MARK {
            assert_eq!((category, pair[1].as_str()), (Some("A03"), None), "the named difference");
            continue;
        }
        assert_eq!(category, pair[1].as_str(), "{declaration:?}");
    }
}

#[test]
fn the_coverage_week_and_the_mttr() {
    let set = read("trends.json");
    for pair in set["weeks"].as_array().unwrap() {
        let at = Instant::parse_java(str_of(&pair[0])).unwrap();
        assert_eq!(owasp_coverage::week_start(at).to_java_string().as_deref(), pair[1].as_str(), "{}", pair[0]);
    }
    for row in set["mttr"].as_array().unwrap() {
        let issues: Vec<mttr::ResolvedIssue> = row["issues"]
            .as_array()
            .unwrap()
            .iter()
            .map(|issue| mttr::ResolvedIssue {
                severity: issue[0]
                    .as_str()
                    .map(|name| vectispire_domain::Severity::of(Some(&name.to_ascii_lowercase()))),
                first_seen_at: issue[1].as_str().map(|at| Instant::parse_java(at).unwrap()),
                resolved_at: issue[2].as_str().map(|at| Instant::parse_java(at).unwrap()),
            })
            .collect();
        assert_eq!(text(&mttr::calculate(&issues)), text(&row["result"]), "{}", row["issues"]);
    }
}

#[test]
fn the_spreadsheet_cells() {
    for pair in read("cells.json")["cells"].as_array().unwrap() {
        assert_eq!(spreadsheet_cells::neutralize(str_of(&pair[0])), str_of(&pair[1]), "{:?}", pair[0]);
    }
}

/// `OwaspMarkdown.parse` over hand-picked reports and seeded mixtures of awkward lines, compared whole — kinds,
/// levels, markers, cells and nulls — and the effective status of a stored review either side of its deadline.
#[test]
fn the_report_markdown_and_the_review_status() {
    let set = read("markdown.json");
    let mut differ = 0usize;
    for case in set["parse"].as_array().unwrap() {
        let input = str_of(&case[0]);
        let ours: Value = serde_json::to_value(vectispire_cp_compliance::markdown::parse(Some(input))).unwrap();
        if ours != case[1] {
            differ += 1;
            if differ <= 5 {
                eprintln!("{input:?}\n  java: {}\n  rust: {ours}", case[1]);
            }
        }
    }
    assert_eq!(differ, 0, "parses differing from Java's");

    let now = time::OffsetDateTime::parse(str_of(&set["now"]), &time::format_description::well_known::Rfc3339).unwrap();
    for row in set["status"].as_array().unwrap() {
        let deadline = row[1]
            .as_str()
            .map(|at| time::OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339).unwrap());
        let stored = str_of(&row[0]);
        assert_eq!(vectispire_cp_compliance::review::effective(stored, deadline, now), str_of(&row[2]), "{row}");
        assert_eq!(vectispire_cp_compliance::review::is_abandoned(stored, deadline, now), row[3].as_bool().unwrap());
    }
    assert_eq!(vectispire_cp_compliance::review::ABANDONED, str_of(&set["abandoned"]));
}
