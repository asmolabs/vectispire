//! checkov's report (a report, a list of reports, or the bare summary of an empty tree): whatever it holds,
//! reading it must answer, never panic — and a shape that is not checkov's is absent, never "clean".
#![no_main]

use libfuzzer_sys::fuzz_target;
use vectispire_container::ContainerResult;

fuzz_target!(|data: &[u8]| {
    let Ok(report) = std::str::from_utf8(data) else { return };
    let result = ContainerResult { stdout: report.to_owned(), stderr: String::new(), exit_code: 0 };
    let _ = vectispire_scanners::iac::outcome(&result, None);
    let _ = vectispire_scanners::iac::outcome(&result, Some("deploy"));
});
