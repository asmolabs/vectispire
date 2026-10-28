//! semgrep's report is written by a container that read the target's files, and its paths and messages
//! are the repository's own: whatever it holds, reading it — with or without a sub-path — must answer
//! (findings, absent or a failure), never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vectispire_container::ContainerResult;

fuzz_target!(|data: &[u8]| {
    let Ok(report) = std::str::from_utf8(data) else { return };
    let result = ContainerResult { stdout: report.to_owned(), stderr: String::new(), exit_code: 0 };
    let _ = vectispire_scanners::sast::outcome(&result, None);
    let _ = vectispire_scanners::sast::outcome(&result, Some("service/api"));
});
