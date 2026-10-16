//! The SAST step against the Java step's answers for every run in `reference/sast/runs/` — the
//! pinned semgrep's real output with the bundled and operator rules, and the edges — byte for byte.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod scanner_runs;

use vectispire_container::ContainerResult;
use vectispire_scanners::sast;

#[test]
fn every_run_gives_the_java_outcome_byte_for_byte() {
    scanner_runs::compare("sast", |run| {
        scanner_runs::outcome_text(sast::outcome(&run.result, run.sub_path.as_deref()))
    });
}

#[test]
fn a_refused_rule_file_is_a_failure_that_names_it() {
    let run = scanner_runs::runs("sast").into_iter().find(|run| run.name == "05-invalid-rule").unwrap();
    let failure = sast::outcome(&run.result, None).unwrap_err().to_string();
    assert!(failure.contains("InvalidRuleSchemaError"), "{failure}");
}

#[test]
fn a_tree_the_target_ignored_entirely_is_absent_not_clean() {
    let run = scanner_runs::runs("sast").into_iter().find(|run| run.name == "03-semgrepignore-everything").unwrap();
    assert!(matches!(sast::outcome(&run.result, None), Ok(None)));
}

#[test]
fn the_owasp_edition_is_read_with_an_ascii_word_boundary() {
    assert_eq!(sast::category_of("A01:2017 - Injection"), None);
    assert_eq!(sast::category_of("éA03:2021").as_deref(), Some("A03"));
    assert_eq!(sast::category_of("_A03:2021"), None);
    assert_eq!(sast::category_of("A03:2021x"), None);
}

/// Decision 0007, as it should read once the Java side is fixed: a report whose `results` is not an
/// array has no findings to read — absent, not "clean". Today both sides answer an empty list
/// (`reference/sast/runs/18-results-not-an-array`); un-ignore when the reference set is regenerated.
#[test]
#[ignore = "pending the Java fix of decision 0007's defect class — see the docs of sast::outcome"]
fn pending_0007_a_report_without_results_is_absent() {
    let result = ContainerResult {
        stdout: r#"{"results": {"a": 1}, "errors": [], "paths": {"scanned": ["/repo/source/a.py"]}}"#.to_owned(),
        stderr: String::new(),
        exit_code: 0,
    };
    assert!(matches!(sast::outcome(&result, None), Ok(None)));
}
