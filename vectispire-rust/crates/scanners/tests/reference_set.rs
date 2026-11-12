//! The secrets parser against the Java parser's answers for every report in
//! `reference/secrets/reports/` — byte for byte, as the agent's JSON mapper writes them, and `null`
//! where the report is not one (absent: the scan then fails the step, decision 0007).

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[test]
fn every_report_gives_the_java_findings_byte_for_byte() {
    let reports = vectispire_testkit::reference_root().join("secrets/reports");
    let mut names: Vec<_> = std::fs::read_dir(&reports)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".json"))
        .collect();
    names.sort();
    assert!(names.len() >= 10, "the reference set is there: {names:?}");
    let mut differences = Vec::new();
    for name in &names {
        let content = std::fs::read_to_string(reports.join(name)).unwrap();
        let ours = serde_json::to_string(&vectispire_scanners::secrets::read(&content)).unwrap() + "\n";
        let java = vectispire_testkit::read(&format!("secrets/findings/{name}"));
        if ours != java {
            differences.push(format!("{name}\n  java: {java}  rust: {ours}"));
        }
    }
    assert!(differences.is_empty(), "the findings differ — a fingerprint change:\n{}", differences.join("\n"));
}

#[test]
fn only_an_empty_array_is_a_clean_report() {
    // The one clean answer is `[]`; every shape the old reading took for "no secrets" is absent now.
    assert_eq!(vectispire_scanners::secrets::read("[]"), Some(Vec::new()));
    for not_a_report in ["", "  \n", "{}", "null", "42", "[1]", "[{}] x", "\u{feff}[]", "[{} , null]"] {
        assert_eq!(vectispire_scanners::secrets::read(not_a_report), None, "{not_a_report:?}");
    }
}
