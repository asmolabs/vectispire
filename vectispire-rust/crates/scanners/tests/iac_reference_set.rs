//! The IaC step against the Java step's answers for every run in `reference/iac/runs/` — the
//! pinned checkov's real output on small trees, and the edges — byte for byte.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod scanner_runs;

use vectispire_container::ContainerResult;
use vectispire_scanners::iac;

#[test]
fn every_run_gives_the_java_outcome_byte_for_byte() {
    scanner_runs::compare("iac", |run| {
        scanner_runs::outcome_text::<_, std::convert::Infallible>(Ok(iac::outcome(
            &run.result,
            run.sub_path.as_deref(),
        )))
    });
}

#[test]
fn a_real_mixed_repository_reports_every_framework() {
    let run = scanner_runs::runs("iac").into_iter().find(|run| run.name == "02-mixed-frameworks").unwrap();
    let findings = iac::outcome(&run.result, None).expect("a report");
    for prefix in ["infra/", "k8s/", "Dockerfile"] {
        assert!(findings.iter().any(|finding| finding.file.starts_with(prefix)), "{prefix}: {findings:?}");
    }
}

fn stdout(text: &str) -> ContainerResult {
    ContainerResult { stdout: text.to_owned(), stderr: String::new(), exit_code: 0 }
}

/// Decision 0007: a document that is no checkov report says nothing was analysed — absent, not
/// "clean" (`reference/iac/runs/16-…` to `20-…`).
#[test]
fn a_document_that_is_no_report_is_absent() {
    for garbage in [
        "\"done\"",
        "{}",
        "[]",
        "{\"results\": \"x\"}",
        "[1, 2]",
        "{\"results\": {\"failed_checks\": {}}}",
        "{\"results\": {\"failed_checks\": [1]}}",
        "{\"resource_count\": 1.0, \"checkov_version\": \"3\"}",
    ] {
        assert_eq!(iac::outcome(&stdout(garbage), None), None, "{garbage}");
    }
}

#[test]
fn the_empty_summary_of_a_tree_without_infrastructure_stays_an_empty_list() {
    // The real answer for a tree with nothing to check: analysed, nothing failed. The refusals above
    // must keep it.
    let run = scanner_runs::runs("iac").into_iter().find(|run| run.name == "03-no-infrastructure").unwrap();
    assert_eq!(iac::outcome(&run.result, None), Some(Vec::new()));
}
