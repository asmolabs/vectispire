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

/// Decision 0007, as it should read once the Java side is fixed: a document that is no checkov
/// report says nothing was analysed — absent, not "clean". Today both sides answer an empty list
/// (`reference/iac/runs/18-…` to `20-…`); un-ignore when the reference set is regenerated after the fix.
#[test]
#[ignore = "pending the Java fix of decision 0007's defect class — see the docs of iac::outcome"]
fn pending_0007_a_document_that_is_no_report_is_absent() {
    for garbage in ["\"done\"", "{}", "{\"results\": \"x\"}", "[1, 2]"] {
        assert_eq!(iac::outcome(&stdout(garbage), None), None, "{garbage}");
    }
}

#[test]
fn the_empty_summary_of_a_tree_without_infrastructure_stays_an_empty_list() {
    // The real answer for a tree with nothing to check: analysed, nothing failed. The corrected
    // reading above must keep it.
    let run = scanner_runs::runs("iac").into_iter().find(|run| run.name == "03-no-infrastructure").unwrap();
    assert_eq!(iac::outcome(&run.result, None), Some(Vec::new()));
}
