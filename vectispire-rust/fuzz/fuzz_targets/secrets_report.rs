//! gitleaks' report is written by a container that read the target's files: whatever it holds, reading
//! it must answer, never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(report) = std::str::from_utf8(data) else { return };
    let _ = vectispire_scanners::secrets::read_report(report);
});
