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

/// Decision 0007: a report whose `results` is not an array, or holds something other than objects, is
/// a report of another shape — the step fails, it never reads "clean"
/// (`reference/sast/runs/18-results-not-an-array`, `23-field-types`).
#[test]
fn a_report_without_results_fails_the_step() {
    for (stdout, said) in [
        (r#"{"results": {"a": 1}, "errors": [], "paths": {"scanned": ["/repo/source/a.py"]}}"#, sast::NO_RESULTS),
        (r#"{"errors": [], "paths": {"scanned": ["/repo/source/a.py"]}}"#, sast::NO_RESULTS),
        (r#"{"results": [1], "errors": [], "paths": {"scanned": ["/repo/source/a.py"]}}"#, sast::RESULT_NOT_AN_OBJECT),
    ] {
        let result = ContainerResult { stdout: stdout.to_owned(), stderr: String::new(), exit_code: 0 };
        let error = sast::outcome(&result, None).expect_err(stdout);
        assert_eq!(error.to_string(), said, "{stdout}");
    }
}
