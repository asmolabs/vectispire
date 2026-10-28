//! The recorded container results of `reference/<scanner>/runs/` and the outcome file format of
//! `ScannerRuns` on the Java side: `findings` and the wire JSON, `absent`, or `failure` and the message.

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use vectispire_container::ContainerResult;

/// One recorded run: its name, the result, the sub-path it was scanned with.
pub struct Run {
    pub name: String,
    pub result: ContainerResult,
    pub sub_path: Option<String>,
}

pub fn runs(scanner: &str) -> Vec<Run> {
    let dir = vectispire_testkit::reference_root().join(scanner).join("runs");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter_map(|name| name.strip_suffix(".stdout").map(str::to_owned))
        .collect();
    names.sort();
    assert!(names.len() >= 10, "the {scanner} reference set is there: {names:?}");
    names
        .into_iter()
        .map(|name| {
            let stdout = std::fs::read_to_string(dir.join(format!("{name}.stdout"))).unwrap();
            let stderr = std::fs::read_to_string(dir.join(format!("{name}.stderr"))).unwrap_or_default();
            let mut exit_code = 0;
            let mut sub_path = None;
            if let Ok(case) = std::fs::read_to_string(dir.join(format!("{name}.case"))) {
                for line in case.lines() {
                    match line.split_once('=') {
                        Some(("exit", value)) => exit_code = value.parse().unwrap(),
                        Some(("subPath", value)) => sub_path = Some(value.to_owned()),
                        _ => {}
                    }
                }
            }
            Run { name, result: ContainerResult { stdout, stderr, exit_code }, sub_path }
        })
        .collect()
}

/// The outcome as `ScannerRuns.expectOutcomes` writes it.
pub fn outcome_text<T: serde::Serialize, E: std::fmt::Display>(outcome: Result<Option<Vec<T>>, E>) -> String {
    match outcome {
        Ok(Some(findings)) => format!("findings\n{}\n", serde_json::to_string(&findings).unwrap()),
        Ok(None) => "absent\n".to_owned(),
        Err(failure) => format!("failure\n{failure}\n"),
    }
}

/// Every run's outcome against the Java side's, the differences listed.
pub fn compare(scanner: &str, outcome: impl Fn(&Run) -> String) {
    let mut differences = Vec::new();
    for run in runs(scanner) {
        let ours = outcome(&run);
        let java = vectispire_testkit::read(&format!("{scanner}/outcomes/{}.txt", run.name));
        if ours != java {
            differences.push(format!("{}\n  java: {java}  rust: {ours}", run.name));
        }
    }
    assert!(
        differences.is_empty(),
        "the outcomes differ — a fingerprint or a backlog change:\n{}",
        differences.join("\n")
    );
}
